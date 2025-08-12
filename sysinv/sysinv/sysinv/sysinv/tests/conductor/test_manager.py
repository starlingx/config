# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8

# Copyright 2013 Hewlett-Packard Development Company, L.P.
# Copyright 2013 International Business Machines Corporation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# Copyright (c) 2013-2025 Wind River Systems, Inc.
#

"""Test class for Sysinv ManagerService."""

import copy
import io
import mock
import os.path
import netaddr
import uuid
import threading
from time import sleep

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from fm_api import constants as fm_constants
from oslo_context import context
from oslo_serialization import base64
from sysinv.agent import rpcapi as agent_rpcapi
from sysinv.common import constants
from sysinv.common import device as dconstants
from sysinv.common import exception
from sysinv.common import kubernetes
from sysinv.common import utils as cutils
from sysinv.common import usm_service
from sysinv.conductor import kube_app
from sysinv.conductor import manager
from sysinv.db import api as dbapi
from sysinv.tests.db import utils as dbutils

from sysinv.tests.db import base
from sysinv.tests.db import utils


class FakeSecret(object):

    def __init__(self, crt):
        self.data = {'tls.crt': base64.encode_as_text(crt)}


class FakeCephOperator(object):

    def __init__(self, db_api):
        self.dbapi = dbapi


class FakePuppetOperator(object):

    def __init__(self, db_api):
        self.dbapi = dbapi
        self.update_host_config = mock.MagicMock()
        self.update_system_config = mock.MagicMock()
        self.update_secure_system_config = mock.MagicMock()


class FakeKubeOperator(object):
    def __init__(self):
        self.kubeadm_configmap_reformat = mock.MagicMock()


class FakePopen(object):

    def __init__(self, **kwargs):
        # Pretend all is OK
        self.returncode = 0

    def communicate(self):
        return "Fake stdout", "Fake stderr"


class ManagerTestCase(base.DbTestCase):

    def extract_certs_from_pem(self, pem_contents):
        """
        Extract certificates from a pem string

        :param pem_contents: A string in pem format
        :return certs: A list of x509 cert objects
        """
        marker = b'-----BEGIN CERTIFICATE-----'

        start = 0
        certs = []
        while True:
            index = pem_contents.find(marker, start)
            if index == -1:
                break
            try:
                cert = x509.load_pem_x509_certificate(pem_contents[index::],
                                                    default_backend())
            except Exception:
                raise exception.SysinvException((
                    "Failed to load pem x509 certificate"))

            certs.append(cert)
            start = index + len(marker)
        return certs

    def setUp(self):

        self.kubeadm_config_read = kubernetes.client.V1ConfigMap(
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
                                            '    feature-gates: CSIMigrationPortworx=false\n'
                                            '  extraVolumes:\n'
                                            'kind: ClusterConfiguration\n'
                                            'kubernetesVersion: v1.42.1\n'
                                            'scheduler: {}\n'},

            metadata=kubernetes.client.V1ObjectMeta(
                        name='kubeadm-config',
                        namespace='kube-system'),
        )
        config_patch = 'apiServer:\n  certSANs: [192.168.206.1, 127.0.0.1, 10.10.6.3]\n  '
        config_patch += 'extraArgs: {event-ttl: 24h}\n  extraVolumes:\n  - {hostPath: '
        config_patch += '/etc/kubernetes/encryption-provider.yaml}\napiVersion: '
        config_patch += 'kubeadm.k8s.io/v1beta3\ncontrollerManager:\n  extraArgs: '
        config_patch += '{feature-gates: CSIMigrationPortworx=false}\n'
        config_patch += '  extraVolumes: null\nkind: ClusterConfiguration\nkubernetesVersion: '
        config_patch += 'v1.42.1\nscheduler: {}\n'
        self.kubeadm_config_map_patch = {'data': {'ClusterConfiguration': config_patch}}

        self.kubeadm_config_read_RemoveSelfLink = kubernetes.client.V1ConfigMap(
            api_version='v1',
            data={'ClusterConfiguration': 'apiServer:\n'
                                            '  certSANs:\n'
                                            '  - 192.168.206.1\n'
                                            '  - 127.0.0.1\n'
                                            '  - 10.10.6.3\n'
                                            '  extraArgs:\n'
                                            '    event-ttl: 24h\n'
                                            '    feature-gates: RemoveSelfLink=false\n'
                                            '  extraVolumes:\n'
                                            '  - hostPath: '
                                            '/etc/kubernetes/encryption-provider.yaml\n'
                                            'apiVersion: kubeadm.k8s.io/v1beta3\n'
                                            'controllerManager:\n'
                                            '  extraArgs:\n'
                                            '    feature-gates: CSIMigrationPortworx=false,RemoveSelfLink=false\n'
                                            '  extraVolumes:\n'
                                            'kind: ClusterConfiguration\n'
                                            'kubernetesVersion: v1.42.1\n'
                                            'scheduler: {}\n'},

            metadata=kubernetes.client.V1ObjectMeta(
                        name='kubeadm-config',
                        namespace='kube-system'),
        )
        selflink_patch = 'apiServer:\n  certSANs: [192.168.206.1, 127.0.0.1, 10.10.6.3]\n  '
        selflink_patch += 'extraArgs: {event-ttl: 24h}\n  extraVolumes:\n  - {hostPath: '
        selflink_patch += '/etc/kubernetes/encryption-provider.yaml}\napiVersion: '
        selflink_patch += 'kubeadm.k8s.io/v1beta3\ncontrollerManager:\n  extraArgs: '
        selflink_patch += '{feature-gates: CSIMigrationPortworx=false}\n'
        selflink_patch += '  extraVolumes: null\nkind: '
        selflink_patch += 'ClusterConfiguration\nkubernetesVersion: v1.42.1\nscheduler: {}\n'
        self.kubeadm_config_map_patch_RemoveSelfLink = {'data': {'ClusterConfiguration': selflink_patch}}

        self.kubeadm_config_map_read_etcd_endpoints = kubernetes.client.V1ConfigMap(
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
                                            '    feature-gates: CSIMigrationPortworx=false\n'
                                            '  extraVolumes:\n'
                                            'etcd:\n'
                                            '  external:\n'
                                            '    caFile: /etc/etcd/ca.crt\n'
                                            '    certFile: /etc/kubernetes/pki/apiserver-etcd-client.crt\n'
                                            '    endpoints:\n'
                                            '    - https://127.0.0.1:2379\n'
                                            '    - https://192.168.206.1:2379\n'
                                            '    - https://192.168.206.3:2379\n'
                                            '    keyFile: /etc/kubernetes/pki/apiserver-etcd-client.key\n'
                                            'kind: ClusterConfiguration\n'
                                            'kubernetesVersion: v1.42.1\n'
                                            'scheduler: {}\n'},

            metadata=kubernetes.client.V1ObjectMeta(
                        name='kubeadm-config',
                        namespace='kube-system'),
        )

        self.kubeadm_config_map_patch_etcd_endpoints = \
            {'data':
             {'ClusterConfiguration': 'apiServer:\n'
                                        '  certSANs: [192.168.206.1, 127.0.0.1, 10.10.6.3]\n'
                                        '  extraArgs: {event-ttl: 24h}\n'
                                        '  extraVolumes:\n'
                                        '  - {hostPath: /etc/kubernetes/encryption-provider.yaml}\n'
                                        'apiVersion: kubeadm.k8s.io/v1beta3\n'
                                        'controllerManager:\n'
                                        '  extraArgs: {feature-gates: CSIMigrationPortworx=false}\n'
                                        '  extraVolumes: null\n'
                                        'etcd:\n'
                                        '  external:\n'
                                        '    caFile: /etc/etcd/ca.crt\n'
                                        '    certFile: /etc/kubernetes/pki/apiserver-etcd-client.crt\n'
                                        '    endpoints: [https://192.168.206.1:2379]\n'
                                        '    keyFile: /etc/kubernetes/pki/apiserver-etcd-client.key\n'
                                        'kind: ClusterConfiguration\n'
                                        'kubernetesVersion: v1.42.1\n'
                                        'scheduler: {}\n'}}

        super(ManagerTestCase, self).setUp()

        # Set up objects for testing
        self.service = manager.ConductorManager('test-host', 'test-topic')
        self.service.dbapi = dbapi.get_instance()
        self.service._docker = kube_app.DockerHelper(self.service.dbapi)
        self.context = context.get_admin_context()
        self.dbapi = dbapi.get_instance()
        self.system = utils.create_test_isystem()
        self.dnsmasq_hosts_file = '/tmp/dnsmasq.hosts'

        # Mock the ceph operator
        self.fake_ceph_operator = FakeCephOperator(self.dbapi)
        p = mock.patch('sysinv.conductor.ceph.CephOperator')
        self.mock_ceph_operator = p.start()
        self.mock_ceph_operator.return_value = self.fake_ceph_operator
        self.addCleanup(p.stop)

        # Mock the puppet operator
        self.fakepuppet_operator = FakePuppetOperator(self.dbapi)
        p = mock.patch('sysinv.puppet.puppet.PuppetOperator')
        self.mockpuppet_operator = p.start()
        self.mockpuppet_operator.return_value = self.fakepuppet_operator
        self.addCleanup(p.stop)
        self.service._puppet = self.fakepuppet_operator

        self.write_config_patcher = mock.patch.object(
            manager.ConductorManager, '_write_config')
        self.mock_write_config = \
            self.write_config_patcher.start()
        self.addCleanup(self.mock_write_config.stop)

        self.service.fm_api = mock.Mock()
        self.service.fm_api.set_fault.side_effect = self._raise_alarm
        self.service.fm_api.clear_fault.side_effect = self._clear_alarm
        self.service.fm_api.get_faults_by_id.side_effect = self._get_faults_by_id

        # Mock sw_version check since tox tsc.SW_VERSION is "TEST.SW_VERSION"
        self.host_load_matches_sw_version_patcher = mock.patch.object(
            manager.ConductorManager, 'host_load_matches_sw_version')
        self.mock_host_load_matches_sw_version = \
            self.host_load_matches_sw_version_patcher.start()
        self.usm_service_get_by_hostname_patcher = mock.patch.object(
            usm_service.UsmHostUpgrade, 'get_by_hostname')
        self.mock_usm_service_get_by_hostname = \
            self.usm_service_get_by_hostname_patcher.start()
        self.mock_host_load_matches_sw_version.return_value = True
        self.addCleanup(self.host_load_matches_sw_version_patcher.stop)

        self.fail_config_apply_runtime_manifest = False

        # Mock ready to apply runtime config
        self._ready_to_apply_runtime_config = True
        self.ready_to_apply_runtime_config_patcher = mock.patch.object(
            manager.ConductorManager, '_ready_to_apply_runtime_config')
        self.mock_ready_to_apply_runtime_config = \
            self.ready_to_apply_runtime_config_patcher.start()
        self.mock_ready_to_apply_runtime_config.return_value = \
            self._ready_to_apply_runtime_config
        self.addCleanup(self.ready_to_apply_runtime_config_patcher.stop)

        # Mock check_cert_validity
        def mock_cert_validity(obj):
            return None
        self.mocked_cert_validity = mock.patch.object(cutils, 'check_cert_validity', mock_cert_validity)
        self.mocked_cert_validity.start()
        self.addCleanup(self.mocked_cert_validity.stop)

        # Mock agent config_apply_runtime_manifest
        def mock_agent_config_apply_runtime_manifest(obj, context, config_uuid,
                                                      config_dict):
            if not self.fail_config_apply_runtime_manifest:
                # Pretend the config was applied
                if 'host_uuids' in config_dict:
                    for host_uuid in config_dict['host_uuids']:
                        self.dbapi.ihost_update(host_uuid,
                                                {'config_applied': config_uuid})
                else:
                    for personality in config_dict['personalities']:
                        hosts = self.dbapi.ihost_get_by_personality(personality)
                        for host in hosts:
                            self.dbapi.ihost_update(
                                host.uuid, {'config_applied': config_uuid})

        self.mocked_rpcapi_config_apply_runtime_manifest = mock.patch.object(
            agent_rpcapi.AgentAPI, 'config_apply_runtime_manifest',
            mock_agent_config_apply_runtime_manifest)
        self.mocked_rpcapi_config_apply_runtime_manifest.start()
        self.addCleanup(self.mocked_rpcapi_config_apply_runtime_manifest.stop)

        self.mock_kube_create_secret = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_create_secret',
            self.mock_kube_create_secret)
        p.start()
        self.addCleanup(p.stop)

        self.mock_kube_create_issuer = mock.MagicMock()
        q = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.apply_custom_resource',
            self.mock_kube_create_issuer)
        q.start()
        self.addCleanup(q.stop)

        self.mock_get_current_kube_rootca = mock.MagicMock()
        z = mock.patch(
            'sysinv.common.utils.get_certificate_from_file',
            self.mock_get_current_kube_rootca
        )
        self.mock_current_kube_rootca = z.start()

        file = os.path.join(os.path.dirname(__file__), "../api", "data",
                                'ca-cert-one-cert.pem')
        with open(file, 'rb') as certfile:
            certfile.seek(0, os.SEEK_SET)
            f = certfile.read()
            self.mock_get_current_kube_rootca.return_value = self.extract_certs_from_pem(f)[0]

        self.addCleanup(z.stop)

        self.fail_config_apply_runtime_manifest = False

        # Mock agent iconfig_update_file
        def mock_agent_iconfig_update_file(obj, context, iconfig_uuid, iconfig_dict):
            if not self.fail_config_apply_runtime_manifest:
                # Simulate the config was applied
                if 'host_uuids' in iconfig_dict:
                    for host_uuid in iconfig_dict['host_uuids']:
                        self.dbapi.ihost_update(host_uuid,
                                                {'config_applied': iconfig_uuid})
                else:
                    for personality in iconfig_dict['personalities']:
                        hosts = self.dbapi.ihost_get_by_personality(personality)
                        for host in hosts:
                            self.dbapi.ihost_update(
                                host.uuid, {'config_applied': iconfig_uuid})

        self.mocked_rpcapi_iconfig_update_file = mock.patch.object(
            agent_rpcapi.AgentAPI, 'iconfig_update_file',
            mock_agent_iconfig_update_file)
        self.mocked_rpcapi_iconfig_update_file.start()
        self.addCleanup(self.mocked_rpcapi_iconfig_update_file.stop)

        self.mocked_is_initial_config_complete = mock.patch.object(
            cutils, 'is_initial_config_complete')
        self.mocked_is_initial_config_complete.start()
        self.mocked_is_initial_config_complete.return_value = True
        self.addCleanup(self.mocked_is_initial_config_complete.stop)

        # Mock subprocess popen
        self.fake_subprocess_popen = FakePopen()
        p = mock.patch('eventlet.green.subprocess.Popen')
        self.mock_subprocess_popen = p.start()
        self.mock_subprocess_popen.return_value = self.fake_subprocess_popen
        self.addCleanup(p.stop)

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

        self.kube_get_kubernetes_version_result = "v1.26.1"

        def mock_kube_get_kubernetes_version(object):
            return self.kube_get_kubernetes_version_result
        self.mocked_kube_get_kubernetes_version = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_get_kubernetes_version',
            mock_kube_get_kubernetes_version)
        self.mocked_kube_get_kubernetes_version.start()
        self.addCleanup(self.mocked_kube_get_kubernetes_version.stop)

        # Mock KubeAppBundleDatabase
        self.bundle_metadata_list = [
            mock.MagicMock(version="1.0.5",
                           k8s_minimum_version="1.26.1",
                           k8s_maximum_version="1.26.1",
                           auto_update=True,
                           file_path="/path/to/bundle1"),
            mock.MagicMock(version="1.1.0",
                           k8s_minimum_version="1.26.1",
                           k8s_maximum_version=None,
                           auto_update=False,
                           file_path="/path/to/bundle2"),
            mock.MagicMock(version="1.2.0",
                           k8s_minimum_version="1.27",
                           k8s_maximum_version=None,
                           auto_update=True,
                           file_path="/path/to/bundle3"),
            mock.MagicMock(version="1.2.5",
                           k8s_minimum_version="1.27",
                           k8s_maximum_version="1.28",
                           auto_update=True,
                           file_path="/path/to/bundle4"),
        ]

        def mock_kube_app_bundle_storage_get_all(*args):
            return self.bundle_metadata_list
        self.mocked_kube_app_bundle_storage_get_all = mock.patch(
            'sysinv.conductor.manager.KubeAppBundleDatabase.get_all',
            mock_kube_app_bundle_storage_get_all)
        self.mocked_kube_app_bundle_storage_get_all.start()
        self.addCleanup(self.mocked_kube_app_bundle_storage_get_all.stop)

        def mock_kube_app_bundle_storage_create_all(*args):
            return True
        self.mocked_kube_app_bundle_storage_create_all = mock.patch(
            'sysinv.conductor.manager.KubeAppBundleDatabase.create_all',
            mock_kube_app_bundle_storage_create_all)
        self.mocked_kube_app_bundle_storage_create_all.start()
        self.addCleanup(self.mocked_kube_app_bundle_storage_create_all.stop)

        # Mock app_metadata.py
        self.extract_bundle_metadata_result = {"key": "value"}

        def mock_bundle_metadata(obj):
            return self.extract_bundle_metadata_result
        self.mocked_extract_bundle_metadata = mock.patch(
            'sysinv.common.app_metadata.extract_bundle_metadata',
            mock_bundle_metadata)
        self.mocked_extract_bundle_metadata.start()
        self.addCleanup(self.mocked_extract_bundle_metadata.stop)

        # Mock the KubeVersion
        self.get_kube_versions_result = [
            {'version': 'v1.41.1',
             'upgrade_from': [],
             'downgrade_to': [],
             'applied_patches': [],
             'available_patches': [],
             },
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
            {'version': 'v1.43.1',
             'upgrade_from': ['v1.43.1'],
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

        self.kube_read_clusterrolebinding_result = kubernetes.client.V1ClusterRoleBinding(
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

        mock_kube_read_clusterrolebinding = mock.MagicMock()
        self.mocked_kube_read_clusterrolebinding = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_read_clusterrolebinding',
            mock_kube_read_clusterrolebinding)
        self.mocked_kube_read_clusterrolebinding.start().return_value = self.kube_read_clusterrolebinding_result
        self.addCleanup(self.mocked_kube_read_clusterrolebinding.stop)
        self.mock_kube_read_clusterrolebinding = mock_kube_read_clusterrolebinding

        mock_kube_patch_clusterrolebinding = mock.MagicMock()
        self.mocked_kube_patch_clusterrolebinding = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_patch_clusterrolebinding',
            mock_kube_patch_clusterrolebinding)
        self.mocked_kube_patch_clusterrolebinding.start().return_value = self.kube_read_clusterrolebinding_result
        self.addCleanup(self.mocked_kube_patch_clusterrolebinding.stop)
        self.mock_kube_patch_clusterrolebinding = mock_kube_patch_clusterrolebinding

        self.service._puppet = mock.Mock()
        self.service._allocate_addresses_for_host = mock.Mock()
        self.service._update_pxe_config = mock.Mock()
        self.service._ceph_mon_create = mock.Mock()
        self.service._sx_to_dx_post_migration_actions = mock.Mock()
        self.service._initialize_ostree_inotify = mock.Mock()
        self.alarm_raised = False
        self.kernel_alarms = {}

        # Mock utility function
        self.kube_min_version_result, self.kube_max_version_result = 'v1.42.1', 'v1.43.1'

        def mock_get_app_supported_kube_version(app_name, app_version):
            return self.kube_min_version_result, self.kube_max_version_result
        self.mocked_kube_min_version = mock.patch(
            'sysinv.common.utils.get_app_supported_kube_version',
            mock_get_app_supported_kube_version)
        self.mocked_kube_max_version = mock.patch(
            'sysinv.common.utils.get_app_supported_kube_version',
            mock_get_app_supported_kube_version)
        self.mocked_kube_min_version.start()
        self.mocked_kube_max_version.start()
        self.addCleanup(self.mocked_kube_min_version.stop)
        self.addCleanup(self.mocked_kube_max_version.stop)

    def tearDown(self):
        super(ManagerTestCase, self).tearDown()

    def _create_test_ihost(self, **kwargs):
        # ensure the system ID for proper association
        kwargs['forisystemid'] = self.system['id']
        ihost_dict = utils.get_test_ihost(**kwargs)
        # Let DB generate ID if it isn't specified explicitly
        if 'id' not in kwargs:
            del ihost_dict['id']
        ihost = self.dbapi.ihost_create(ihost_dict)
        return ihost

    def test_create_ihost(self):
        ihost_dict = {'mgmt_mac': '00:11:22:33:44:55'}

        self.service.start()
        res = self.service.create_ihost(self.context, ihost_dict)
        self.assertEqual(res['mgmt_mac'], '00:11:22:33:44:55')

    def test_create_duplicate_ihost(self):
        ihost_dict = {'mgmt_mac': '00:11:22:33:44:55'}

        self.service.start()
        # Create first ihost
        res1 = self.service.create_ihost(self.context, ihost_dict)
        # Update the serialid
        res1['serialid'] = '1234567890abc'
        res1 = self.service.update_ihost(self.context, res1)

        # Attempt to create duplicate ihost
        res2 = self.service.create_ihost(self.context, ihost_dict)

        # Verify that original ihost was returned
        self.assertEqual(res1['serialid'], res2['serialid'])

    def test_create_ihost_without_mac(self):
        ihost_dict = {}

        self.assertRaises(exception.SysinvException,
                          self.service.create_ihost,
                          self.context,
                          ihost_dict)

        # verify create did not happen
        res = self.dbapi.ihost_get_list()
        self.assertEqual(len(res), 0)

    def test_create_ihost_with_invalid_mac(self):
        ihost_dict = {'mgmt_mac': '52:54:00:59:02:9'}

        self.assertRaises(exception.SysinvException,
                          self.service.create_ihost,
                          self.context,
                          ihost_dict)

        # verify create did not happen
        res = self.dbapi.ihost_get_list()
        self.assertEqual(len(res), 0)

    def test_create_ihost_without_ip(self):
        ihost_dict = {'mgmt_mac': '00:11:22:33:44:55'}

        self.service.start()
        self.service.create_ihost(self.context, ihost_dict)

        # verify create happened
        res = self.dbapi.ihost_get_list()
        self.assertEqual(len(res), 1)

    def test_create_ihost_with_values(self):
        ihost_dict = {'mgmt_mac': '00:11:22:33:44:55',
                      'hostname': 'newhost',
                      'invprovision': 'unprovisioned',
                      'personality': 'worker',
                      'administrative': 'locked',
                      'operational': 'disabled',
                      'availability': 'not-installed',
                      'serialid': '1234567890abc',
                      'boot_device': 'sda',
                      'rootfs_device': 'sda',
                      'hw_settle': '0',
                      'sw_version': '0.0',
                      'install_output': 'text',
                      'console': 'ttyS0,115200',
                      'tboot': ''
                      }

        self.service.start()
        res = self.service.create_ihost(self.context, ihost_dict)

        for k, v in ihost_dict.items():
            self.assertEqual(res[k], v)

    def test_system_node_clusterrolebinding_add_host_success(self):
        self.service.start()
        self.service._system_node_clusterrolebinding_add_host(
                "test_system:test_node:test_hostname-1")
        self.mock_kube_read_clusterrolebinding.assert_called()
        self.mock_kube_patch_clusterrolebinding.assert_called()

    def test_system_node_clusterrolebinding_add_host_already_exists(self):
        mock_kube_read_clusterrolebinding = mock.MagicMock()
        mocked_kube_read_clusterrolebinding = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_read_clusterrolebinding',
            mock_kube_read_clusterrolebinding
        )
        mocked_kube_read_clusterrolebinding.start().return_value = \
            self.kube_read_clusterrolebinding_result
        self.addCleanup(mocked_kube_read_clusterrolebinding.stop)

        mock_kube_patch_clusterrolebinding = mock.MagicMock()
        mocked_kube_patch_clusterrolebinding = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_patch_clusterrolebinding',
            mock_kube_patch_clusterrolebinding
        )
        mocked_kube_patch_clusterrolebinding.start()
        self.addCleanup(mocked_kube_patch_clusterrolebinding.stop)

        self.service.start()
        self.service._system_node_clusterrolebinding_add_host(
            "test_system:test_node:test_hostname")
        mock_kube_read_clusterrolebinding.assert_called()
        mock_kube_patch_clusterrolebinding.assert_called_with(
            "system:node", self.kube_read_clusterrolebinding_result)

    def test_system_node_clusterrolebinding_remove_host_success(self):
        self.service.start()
        self.service._system_node_clusterrolebinding_remove_host(
                "test_system:test_node:test:hostname")
        self.mock_kube_read_clusterrolebinding.assert_called()
        self.mock_kube_patch_clusterrolebinding.assert_called()

    def test_system_node_clusterrolebinding_add_host_exception(self):
        mock_kube_read_clusterrolebinding = mock.MagicMock()
        mocked_kube_read_clusterrolebinding = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_read_clusterrolebinding',
            mock_kube_read_clusterrolebinding
        )
        mocked_kube_read_clusterrolebinding.start().side_effect = Exception("Fake Error")
        self.addCleanup(mocked_kube_read_clusterrolebinding.stop)
        self.service.start()
        self.assertRaises(     # noqa: H202
            Exception,
            self.service._system_node_clusterrolebinding_add_host,
        )

    def test_system_node_clusterrolebinding_remove_host_exception(self):
        mock_kube_patch_clusterrolebinding = mock.MagicMock()
        mocked_kube_patch_clusterrolebinding = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_patch_clusterrolebinding',
            mock_kube_patch_clusterrolebinding
        )
        mocked_kube_patch_clusterrolebinding.start().side_effect = Exception("Fake Error")
        self.addCleanup(mocked_kube_patch_clusterrolebinding.stop)
        self.service.start()
        self.assertRaises(     # noqa: H202
            Exception,
            self.service._system_node_clusterrolebinding_remove_host,
        )

    def test_update_ihost(self):
        ihost = self._create_test_ihost()

        ihost['mgmt_mac'] = '00:11:22:33:44:55'
        ihost['hostname'] = 'newhost'
        ihost['invprovision'] = 'unprovisioned'
        ihost['personality'] = 'worker'
        ihost['administrative'] = 'locked'
        ihost['operational'] = 'disabled'
        ihost['availability'] = 'not-installed'
        ihost['serialid'] = '1234567890abc'
        ihost['boot_device'] = 'sda'
        ihost['rootfs_device'] = 'sda'
        ihost['hw_settle'] = '0'
        ihost['sw_version'] = '0.0'
        ihost['install_output'] = 'text'
        ihost['console'] = 'ttyS0,115200'

        res = self.service.update_ihost(self.context, ihost)

        self.assertEqual(res['mgmt_mac'], '00:11:22:33:44:55')
        self.assertEqual(res['hostname'], 'newhost')
        self.assertEqual(res['invprovision'], 'unprovisioned')
        self.assertEqual(res['personality'], 'worker')
        self.assertEqual(res['administrative'], 'locked')
        self.assertEqual(res['operational'], 'disabled')
        self.assertEqual(res['availability'], 'not-installed')
        self.assertEqual(res['serialid'], '1234567890abc')
        self.assertEqual(res['boot_device'], 'sda')
        self.assertEqual(res['rootfs_device'], 'sda')
        self.assertEqual(res['hw_settle'], '0')
        self.assertEqual(res['sw_version'], '0.0')
        self.assertEqual(res['install_output'], 'text')
        self.assertEqual(res['console'], 'ttyS0,115200')

    def test_update_ihost_id(self):
        ihost = self._create_test_ihost()

        ihost['id'] = '12345'
        self.assertRaises(exception.SysinvException,
                          self.service.update_ihost,
                          self.context,
                          ihost)

    def test_update_ihost_uuid(self):
        ihost = self._create_test_ihost()

        ihost['uuid'] = 'asdf12345'
        self.assertRaises(exception.SysinvException,
                          self.service.update_ihost,
                          self.context,
                          ihost)

    def test_configure_ihost_new(self):
        # Test skipped to prevent error message in Jenkins. Error thrown is:
        # in test_configure_ihost_new
        # with open(self.dnsmasq_hosts_file, 'w') as f:
        # IOError: [Errno 13] Permission denied: '/tmp/dnsmasq.hosts'
        self.skipTest("Skipping to prevent failure notification on Jenkins")
        with open(self.dnsmasq_hosts_file, 'w') as f:
            f.write("dhcp-host=08:00:27:0a:fa:fa,worker-1,192.168.204.25,2h\n")

        ihost = self._create_test_ihost()

        ihost['mgmt_mac'] = '00:11:22:33:44:55'
        ihost['hostname'] = 'newhost'
        ihost['invprovision'] = 'unprovisioned'
        ihost['personality'] = 'worker'
        ihost['administrative'] = 'locked'
        ihost['operational'] = 'disabled'
        ihost['availability'] = 'not-installed'
        ihost['serialid'] = '1234567890abc'
        ihost['boot_device'] = 'sda'
        ihost['rootfs_device'] = 'sda'
        ihost['hw_settle'] = '0'
        ihost['sw_version'] = '0.0'
        ihost['install_output'] = 'text'
        ihost['console'] = 'ttyS0,115200'

        self.service.configure_ihost(self.context, ihost)

        with open(self.dnsmasq_hosts_file, 'r') as f:
            self.assertEqual(
                f.readline(),
                "dhcp-host=08:00:27:0a:fa:fa,worker-1,192.168.204.25,2h\n")
            self.assertEqual(
                f.readline(),
                "dhcp-host=00:11:22:33:44:55,newhost,1.2.3.4,2h\n")

    def test_configure_ihost_replace(self):
        # Test skipped to prevent error message in Jenkins. Error thrown is:
        # in test_configure_ihost_replace
        # with open(self.dnsmasq_hosts_file, 'w') as f:
        # IOError: [Errno 13] Permission denied: '/tmp/dnsmasq.hosts'
        self.skipTest("Skipping to prevent failure notification on Jenkins")
        with open(self.dnsmasq_hosts_file, 'w') as f:
            f.write("dhcp-host=00:11:22:33:44:55,oldhost,1.2.3.4,2h\n")
            f.write("dhcp-host=08:00:27:0a:fa:fa,worker-1,192.168.204.25,2h\n")

        ihost = self._create_test_ihost()

        ihost['mgmt_mac'] = '00:11:22:33:44:55'
        ihost['hostname'] = 'newhost'
        ihost['invprovision'] = 'unprovisioned'
        ihost['personality'] = 'worker'
        ihost['administrative'] = 'locked'
        ihost['operational'] = 'disabled'
        ihost['availability'] = 'not-installed'
        ihost['serialid'] = '1234567890abc'
        ihost['boot_device'] = 'sda'
        ihost['rootfs_device'] = 'sda'
        ihost['hw_settle'] = '0'
        ihost['sw_version'] = '0.0'
        ihost['install_output'] = 'text'
        ihost['console'] = 'ttyS0,115200'

        self.service.configure_ihost(self.context, ihost)

        with open(self.dnsmasq_hosts_file, 'r') as f:
            self.assertEqual(
                f.readline(),
                "dhcp-host=00:11:22:33:44:55,newhost,1.2.3.42,2h\n")
            self.assertEqual(
                f.readline(),
                "dhcp-host=08:00:27:0a:fa:fa,worker-1,192.168.204.25,2h\n")

    def test_configure_ihost_no_hostname(self):
        # Test skipped to prevent error message in Jenkins. Error thrown is:
        # in update_dnsmasq_config
        # os.rename(temp_dnsmasq_hosts_file, dnsmasq_hosts_file)
        # OSError: [Errno 1] Operation not permitted
        self.skipTest("Skipping to prevent failure notification on Jenkins")
        ihost = self._create_test_ihost()

        ihost['hostname'] = ''
        self.assertRaises(exception.SysinvException,
                          self.service.configure_ihost,
                          self.context,
                          ihost)

    def test_vim_host_add(self):
        mock_vim_host_add = mock.MagicMock()
        p = mock.patch('sysinv.api.controllers.v1.vim_api.vim_host_add',
                mock_vim_host_add)
        p.start().return_value = {}
        self.addCleanup(p.stop)

        ret = self.service.vim_host_add(self.context, None, str(uuid.uuid4()),
                    "newhostname", "worker", "locked", "disabled", "offline",
                    "disabled", "not-installed", 10)

        mock_vim_host_add.assert_called_with(mock.ANY, mock.ANY,
                "newhostname", "worker", "locked", "disabled", "offline",
                "disabled", "not-installed", 10)

        self.assertEqual(ret, {})

    def test_mtc_host_add(self):
        mock_notify_mtc_and_recv = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.notify_mtc_and_recv',
                    mock_notify_mtc_and_recv)
        p.start().return_value = {'status': 'pass'}
        self.addCleanup(p.stop)

        ihost = {}
        ihost['hostname'] = 'newhost'
        ihost['personality'] = 'worker'

        self.service.mtc_host_add(self.context, "localhost", 2112, ihost)
        mock_notify_mtc_and_recv.assert_called_with("localhost", 2112, ihost)

    def test_ilvg_get_nova_ilvg_by_ihost(self):
        ihost = self._create_test_ihost()
        lvg_dict = {
            'lvm_vg_name': constants.LVG_NOVA_LOCAL,
        }
        ilvg = self.dbapi.ilvg_create(ihost['id'], lvg_dict)
        ret = self.service.ilvg_get_nova_ilvg_by_ihost(self.context, ihost['uuid'])
        self.assertEqual(ret[0]['uuid'], ilvg['uuid'])

    def test_ilvg_get_nova_ilvg_by_ihost_no_nova_ilvg(self):
        ihost = self._create_test_ihost()
        ret = self.service.ilvg_get_nova_ilvg_by_ihost(self.context, ihost['uuid'])
        self.assertEqual(ret, [])

    def test_lldp_neighbour_tlv_update_exceed_length(self):
        # Set up
        ihost = self._create_test_ihost()
        interface = utils.create_test_interface(
            ifname='mgmt',
            forihostid=ihost['id'],
            ihost_uuid=ihost['uuid'],
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            iftype=constants.INTERFACE_TYPE_ETHERNET)
        port = utils.create_test_ethernet_port(
            name='eth0',
            host_id=ihost['id'],
            interface_id=interface['id'],
            pciaddr='0000:00:00.01',
            dev_id=0)

        # create fake neighbour
        neighbour = self.dbapi.lldp_neighbour_create(
            port.id, ihost.id, {
                "msap": "08:00:27:82:35:fb,08:00:27:0d:ac:03"
            })

        # create tlv with excessive size
        tlv_list = self.dbapi.lldp_tlv_get_list()
        bad_size = (
            'enp0s8.100, enp0s8.101, enp0s8.102, enp0s8.103,'
            ' enp0s8.104, enp0s8.105, enp0s8.106, enp0s8.107,'
            ' enp0s8.108, enp0s8.109, enp0s8.110, enp0s8.111,'
            ' enp0s8.112, enp0s8.113, enp0s8.114, enp0s8.115,'
            ' enp0s8.116, enp0s8.117, enp0s8.118, enp0s8.119,'
            ' enp0s8.120, enp0s8.121, enp0s8.122, enp0s8.12,'
            ' enp0s8.123'
        )
        vlan_list = bad_size
        self.service.lldp_neighbour_tlv_update({
            constants.LLDP_TLV_TYPE_DOT1_VLAN_NAMES: vlan_list
        }, neighbour)
        tlv_list = self.dbapi.lldp_tlv_get_list()
        self.assertEqual(tlv_list[0]['value'][-3:], "...")
        self.assertTrue(len(tlv_list[0]['value']) <= 255)

        # update tlv to acceptable size
        vlan_list = 'enp0s8.100'
        self.service.lldp_neighbour_tlv_update({
            constants.LLDP_TLV_TYPE_DOT1_VLAN_NAMES: vlan_list
        }, neighbour)
        tlv_list = self.dbapi.lldp_tlv_get_list()
        self.assertEqual(tlv_list[0]['value'], vlan_list)

        # update tlv to excessive size
        vlan_list = bad_size
        self.service.lldp_neighbour_tlv_update({
            constants.LLDP_TLV_TYPE_DOT1_VLAN_NAMES: vlan_list
        }, neighbour)
        tlv_list = self.dbapi.lldp_tlv_get_list()
        self.assertEqual(tlv_list[0]['value'][-3:], "...")
        self.assertTrue(len(tlv_list[0]['value']) <= 255)

    def test_platform_interfaces(self):
        ihost = self._create_test_ihost()
        interface = utils.create_test_interface(
                ifname='mgmt',
                forihostid=ihost['id'],
                ihost_uuid=ihost['uuid'],
                ifclass=constants.INTERFACE_CLASS_PLATFORM,
                iftype=constants.INTERFACE_TYPE_ETHERNET)
        port = utils.create_test_ethernet_port(
            name='eth0',
            host_id=ihost['id'],
            interface_id=interface['id'],
            pciaddr='0000:00:00.01',
            dev_id=0)

        ret = self.service.platform_interfaces(self.context, ihost['id'])
        self.assertEqual(ret[0]['name'], port['name'])

    def test_platform_interfaces_multi(self):
        ihost = self._create_test_ihost()
        interface_mgmt = utils.create_test_interface(
                ifname='mgmt',
                forihostid=ihost['id'],
                ihost_uuid=ihost['uuid'],
                ifclass=constants.INTERFACE_CLASS_PLATFORM,
                iftype=constants.INTERFACE_TYPE_ETHERNET)
        port_mgmt = utils.create_test_ethernet_port(
            name='eth0',
            host_id=ihost['id'],
            interface_id=interface_mgmt['id'],
            pciaddr='0000:00:00.01',
            dev_id=0)

        interface_oam = utils.create_test_interface(
                ifname='oam',
                forihostid=ihost['id'],
                ihost_uuid=ihost['uuid'],
                ifclass=constants.INTERFACE_CLASS_PLATFORM,
                iftype=constants.INTERFACE_TYPE_ETHERNET)
        port_oam = utils.create_test_ethernet_port(
            name='eth1',
            host_id=ihost['id'],
            interface_id=interface_oam['id'],
            pciaddr='0000:00:00.02',
            dev_id=1)

        interface_data = utils.create_test_interface(
                ifname='data',
                forihostid=ihost['id'],
                ihost_uuid=ihost['uuid'],
                ifclass=constants.INTERFACE_CLASS_DATA,
                iftype=constants.INTERFACE_TYPE_VLAN)
        utils.create_test_ethernet_port(
            name='eth2',
            host_id=ihost['id'],
            interface_id=interface_data['id'],
            pciaddr='0000:00:00.03',
            dev_id=2)

        ret = self.service.platform_interfaces(self.context, ihost['id'])
        self.assertEqual(len(ret), 2)
        self.assertEqual(ret[0]['name'], port_mgmt['name'])
        self.assertEqual(ret[1]['name'], port_oam['name'])

    def test_platform_interfaces_no_port(self):
        ihost = self._create_test_ihost()
        utils.create_test_interface(
                ifname='mgmt',
                forihostid=ihost['id'],
                ihost_uuid=ihost['uuid'],
                ifclass=constants.INTERFACE_CLASS_PLATFORM,
                iftype=constants.INTERFACE_TYPE_ETHERNET)

        ret = self.service.platform_interfaces(self.context, ihost['id'])
        self.assertEqual(ret, [])

    def test_platform_interfaces_invalid_ihost(self):
        ihost = self._create_test_ihost()
        interface = utils.create_test_interface(
                ifname='mgmt',
                forihostid=ihost['id'],
                ihost_uuid=ihost['uuid'],
                ifclass=constants.INTERFACE_CLASS_PLATFORM,
                iftype=constants.INTERFACE_TYPE_ETHERNET)
        utils.create_test_ethernet_port(
            name='eth0',
            host_id=ihost['id'],
            interface_id=interface['id'],
            pciaddr='0000:00:00.01',
            dev_id=0)

        ret = self.service.platform_interfaces(self.context, ihost['id'] + 1)
        self.assertEqual(ret, [])

    def test_kube_pre_application_update(self):
        # Create application
        dbutils.create_test_app(
            name='stx-openstack',
            app_version='1.0-19',
            manifest_name='manifest',
            manifest_file='stx-openstack.yaml',
            status='applied',
            active=True)

        # Create an upgrade
        from_version = 'v1.42.1'
        to_version = 'v1.43.1'
        utils.create_test_kube_upgrade(
            from_version=from_version,
            to_version=to_version,
            state=kubernetes.KUBE_UPGRADE_STARTED,
        )

        # Run update
        self.service.kube_pre_application_update(self.context, to_version)

        # Verify that the upgrade state was updated
        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state,
                         kubernetes.KUBE_PRE_UPDATED_APPS)

    def test_kube_pre_application_update_app_not_compatible(self):
        # Test pre app update step when the installed application isn't
        # compatible with the new kubernetes version

        # Create application
        dbutils.create_test_app(
            name='stx-openstack',
            app_version='1.0-19',
            manifest_name='manifest',
            manifest_file='stx-openstack.yaml',
            status='applied',
            active=True)

        # Create an upgrade
        from_version = 'v1.42.1'
        to_version = 'v1.43.2'
        utils.create_test_kube_upgrade(
            from_version=from_version,
            to_version=to_version,
            state=kubernetes.KUBE_UPGRADE_STARTED,
        )

        # Run update
        self.service.kube_pre_application_update(self.context, to_version)

        # Verify that the upgrade state was updated
        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state,
                         kubernetes.KUBE_PRE_UPDATING_APPS_FAILED)

    def test_kube_upgrade_init_actions(self):
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        # Test the handling of transitory upgrade states
        expected_fail_results = [
            (kubernetes.KUBE_UPGRADE_DOWNLOADING_IMAGES,
             kubernetes.KUBE_UPGRADE_DOWNLOADING_IMAGES_FAILED),
            (kubernetes.KUBE_UPGRADING_FIRST_MASTER,
             kubernetes.KUBE_UPGRADING_FIRST_MASTER_FAILED),
            (kubernetes.KUBE_UPGRADING_NETWORKING,
             kubernetes.KUBE_UPGRADING_NETWORKING_FAILED),
            (kubernetes.KUBE_UPGRADING_SECOND_MASTER,
             kubernetes.KUBE_UPGRADING_SECOND_MASTER_FAILED),
        ]

        for current_state, fail_state in expected_fail_results:
            utils.create_test_kube_upgrade(
                from_version='v1.42.1',
                to_version='v1.42.2',
                state=current_state,
            )
            self.service._kube_upgrade_init_actions()
            updated_upgrade = self.dbapi.kube_upgrade_get_one()
            self.assertEqual(updated_upgrade.state, fail_state)
            self.dbapi.kube_upgrade_destroy(updated_upgrade.id)

        # Test the handling of transitory host upgrade states
        expected_fail_results = [
            (kubernetes.KUBE_HOST_UPGRADING_CONTROL_PLANE,
             kubernetes.KUBE_HOST_UPGRADING_CONTROL_PLANE_FAILED),
            (kubernetes.KUBE_HOST_UPGRADING_KUBELET,
             kubernetes.KUBE_HOST_UPGRADING_KUBELET_FAILED),
        ]

        utils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADING_KUBELETS,
        )

        for current_status, fail_status in expected_fail_results:
            self.dbapi.kube_host_upgrade_update(1, {'status': current_status})
            self.service._kube_upgrade_init_actions()
            updated_host_upgrade = self.dbapi.kube_host_upgrade_get(1)
            self.assertEqual(updated_host_upgrade.status, fail_status)

    def test_kube_download_images_simplex_single_version_success(self):
        """Test download images on simplex and for single-version kubernetes upgrade
        """
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_SIMPLEX
        utils.update_test_isystem(system_dict)

        FROM_VERSION = 'v1.29.2'
        TO_VERSION = 'v1.30.6'
        NEXT_VERSIONS = ['v1.30.6']
        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version=FROM_VERSION,
            to_version=TO_VERSION,
            state=kubernetes.KUBE_UPGRADE_DOWNLOADING_IMAGES,
        )

        mock_kube_get_higher_equal_versions = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_get_higher_patch_version',
            mock_kube_get_higher_equal_versions)
        p.start().return_value = NEXT_VERSIONS
        self.addCleanup(p.stop)

        mock_disable_kubelet_garbage_collection = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.disable_kubelet_garbage_collection',
                       mock_disable_kubelet_garbage_collection)
        p.start()
        self.addCleanup(p.stop)

        mock_pmon_restart_service = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.pmon_restart_service', mock_pmon_restart_service)
        p.start()
        self.addCleanup(p.stop)

        mock_get_k8s_images = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.get_k8s_images', mock_get_k8s_images)
        p.start().return_value = {'fake_key': 'fake_image'}
        self.addCleanup(p.stop)

        mock_download_images_from_upstream_to_local_reg_and_crictl = mock.MagicMock()
        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager.'
            'download_images_from_upstream_to_local_reg_and_crictl',
            mock_download_images_from_upstream_to_local_reg_and_crictl)
        p.start().return_value = True
        self.addCleanup(p.stop)

        # Download images
        self.service.kube_download_images(self.context, TO_VERSION)

        mock_kube_get_higher_equal_versions.assert_called_once_with(FROM_VERSION, TO_VERSION)
        mock_disable_kubelet_garbage_collection.assert_called()
        mock_pmon_restart_service.assert_called()
        self.assertEqual(mock_get_k8s_images.call_count, len(NEXT_VERSIONS))
        mock_download_images_from_upstream_to_local_reg_and_crictl.assert_called_with(
                                                                                    ['fake_image'])
        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state, kubernetes.KUBE_UPGRADE_DOWNLOADED_IMAGES)

    def test_kube_download_images_simplex_multi_version_success(self):
        """Test download images on simplex and for multi-version kubernetes upgrade
        """
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_SIMPLEX
        utils.update_test_isystem(system_dict)

        FROM_VERSION = 'v1.29.2'
        TO_VERSION = 'v1.32.2'
        NEXT_VERSIONS = ['v1.30.6', 'v1.31.5', 'v1.32.2']
        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version=FROM_VERSION,
            to_version=TO_VERSION,
            state=kubernetes.KUBE_UPGRADE_DOWNLOADING_IMAGES,
        )

        mock_kube_get_higher_equal_versions = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_get_higher_patch_version',
            mock_kube_get_higher_equal_versions)
        p.start().return_value = NEXT_VERSIONS
        self.addCleanup(p.stop)

        mock_disable_kubelet_garbage_collection = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.disable_kubelet_garbage_collection',
                       mock_disable_kubelet_garbage_collection)
        p.start()
        self.addCleanup(p.stop)

        mock_pmon_restart_service = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.pmon_restart_service', mock_pmon_restart_service)
        p.start()
        self.addCleanup(p.stop)

        mock_get_k8s_images = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.get_k8s_images', mock_get_k8s_images)
        p.start().return_value = {'fake_key': 'fake_image'}
        self.addCleanup(p.stop)

        mock_download_images_from_upstream_to_local_reg_and_crictl = mock.MagicMock()
        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager.'
            'download_images_from_upstream_to_local_reg_and_crictl',
            mock_download_images_from_upstream_to_local_reg_and_crictl)
        p.start().return_value = True
        self.addCleanup(p.stop)

        # Download images
        self.service.kube_download_images(self.context, TO_VERSION)

        mock_kube_get_higher_equal_versions.assert_called_once_with(FROM_VERSION, TO_VERSION)
        mock_disable_kubelet_garbage_collection.assert_called()
        mock_pmon_restart_service.assert_called()
        self.assertEqual(mock_get_k8s_images.call_count, len(NEXT_VERSIONS))
        mock_download_images_from_upstream_to_local_reg_and_crictl.assert_called_with(
                                                                                    ['fake_image'])
        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state, kubernetes.KUBE_UPGRADE_DOWNLOADED_IMAGES)

    def test_kube_download_images_simplex_fail(self):
        """Test download images on simplex: failure case
        """
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_SIMPLEX
        utils.update_test_isystem(system_dict)

        FROM_VERSION = 'v1.29.2'
        TO_VERSION = 'v1.30.6'
        NEXT_VERSIONS = ['v1.30.6']
        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version=FROM_VERSION,
            to_version=TO_VERSION,
            state=kubernetes.KUBE_UPGRADE_DOWNLOADING_IMAGES,
        )

        mock_kube_get_higher_equal_versions = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_get_higher_patch_version',
            mock_kube_get_higher_equal_versions)
        p.start().return_value = NEXT_VERSIONS
        self.addCleanup(p.stop)

        mock_disable_kubelet_garbage_collection = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.disable_kubelet_garbage_collection',
                       mock_disable_kubelet_garbage_collection)
        # Include a test where GC failed so we need not seperatly test that path.
        p.start().side_effect = Exception("Fake Error")
        self.addCleanup(p.stop)

        mock_pmon_restart_service = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.pmon_restart_service', mock_pmon_restart_service)
        p.start()
        self.addCleanup(p.stop)

        mock_get_k8s_images = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.get_k8s_images', mock_get_k8s_images)
        p.start().return_value = {'fake_key': 'fake_image'}
        self.addCleanup(p.stop)

        mock_download_images_from_upstream_to_local_reg_and_crictl = mock.MagicMock()
        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager.'
            'download_images_from_upstream_to_local_reg_and_crictl',
            mock_download_images_from_upstream_to_local_reg_and_crictl)
        p.start().return_value = False
        self.addCleanup(p.stop)

        # Download images
        self.service.kube_download_images(self.context, TO_VERSION)

        mock_kube_get_higher_equal_versions.assert_called_once_with(FROM_VERSION, TO_VERSION)
        mock_disable_kubelet_garbage_collection.assert_called()
        mock_pmon_restart_service.assert_not_called()
        self.assertEqual(mock_get_k8s_images.call_count, len(NEXT_VERSIONS))
        mock_get_k8s_images.assert_called()
        mock_download_images_from_upstream_to_local_reg_and_crictl.assert_called_with(
                                                                                    ['fake_image'])
        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state, kubernetes.KUBE_UPGRADE_DOWNLOADING_IMAGES_FAILED)

    def test_kube_download_images_duplex_success(self):
        """Test download images on duplex and for single-version kubernetes upgrade success case
        """
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        utils.update_test_isystem(system_dict)

        # Create controller-0
        config_uuid = str(uuid.uuid4())
        controller0_host_uuid = str(uuid.uuid4())
        controller0 = self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=controller0_host_uuid,
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            mgmt_mac='00:11:22:33:44:55'
        )

        # Create controller-1
        config_uuid = str(uuid.uuid4())
        controller1_host_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-1',
            uuid=controller1_host_uuid,
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            mgmt_mac='00:11:22:33:44:56'
        )

        FROM_VERSION = 'v1.29.2'
        TO_VERSION = 'v1.30.6'
        NEXT_VERSIONS = ['v1.30.6']
        FAKE_IMAGE_LIST = ['fake_image']
        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version=FROM_VERSION,
            to_version=TO_VERSION,
            state=kubernetes.KUBE_UPGRADE_DOWNLOADING_IMAGES,
        )

        mock_get_active_controller = mock.MagicMock()
        p = mock.patch('sysinv.api.controllers.v1.utils.HostHelper.get_active_controller',
                       mock_get_active_controller)
        p.start().return_value = controller0
        self.addCleanup(p.stop)

        mock_kube_get_higher_equal_versions = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_get_higher_patch_version',
            mock_kube_get_higher_equal_versions)
        p.start().return_value = NEXT_VERSIONS
        self.addCleanup(p.stop)

        mock_disable_kubelet_garbage_collection = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.disable_kubelet_garbage_collection',
                       mock_disable_kubelet_garbage_collection)
        p.start()
        self.addCleanup(p.stop)

        mock_pmon_restart_service = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.pmon_restart_service', mock_pmon_restart_service)
        p.start()
        self.addCleanup(p.stop)

        mock_get_k8s_images = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.get_k8s_images', mock_get_k8s_images)
        p.start().return_value = {'fake_key': 'fake_image'}
        self.addCleanup(p.stop)

        mock_download_images_from_upstream_to_local_reg_and_crictl = mock.MagicMock()
        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager.'
            'download_images_from_upstream_to_local_reg_and_crictl',
            mock_download_images_from_upstream_to_local_reg_and_crictl)
        p.start().return_value = True
        self.addCleanup(p.stop)

        mock_pull_kubernetes_images = mock.MagicMock()
        p = mock.patch.object(
            agent_rpcapi.AgentAPI, 'pull_kubernetes_images', mock_pull_kubernetes_images)
        p.start()
        self.addCleanup(p.stop)

        # Pretend controller-0 receievs the kube_download_images call
        self.service.host_uuid = controller0_host_uuid
        self.service.kube_download_images(self.context, TO_VERSION)

        mock_kube_get_higher_equal_versions.assert_called_once()
        mock_disable_kubelet_garbage_collection.assert_called_once()
        mock_pmon_restart_service.assert_called_once()
        self.assertEqual(mock_get_k8s_images.call_count, len(NEXT_VERSIONS))
        mock_download_images_from_upstream_to_local_reg_and_crictl.assert_called_with(
                                                                                FAKE_IMAGE_LIST)
        mock_pull_kubernetes_images.assert_called_once_with(
            self.context, controller1_host_uuid, FAKE_IMAGE_LIST)

    def test_kube_download_images_duplex_failure(self):
        """Test download images on duplex and for single-version k8s upgrade: unexpected exception
        """
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        utils.update_test_isystem(system_dict)

        # Create controller-0
        config_uuid = str(uuid.uuid4())
        controller0_host_uuid = str(uuid.uuid4())
        controller0 = self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=controller0_host_uuid,
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            mgmt_mac='00:11:22:33:44:55'
        )

        # Create controller-1
        config_uuid = str(uuid.uuid4())
        controller1_host_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-1',
            uuid=controller1_host_uuid,
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            mgmt_mac='00:11:22:33:44:56'
        )

        FROM_VERSION = 'v1.29.2'
        TO_VERSION = 'v1.30.6'
        NEXT_VERSIONS = ['v1.30.6']
        FAKE_IMAGE_LIST = ['fake_image']
        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version=FROM_VERSION,
            to_version=TO_VERSION,
            state=kubernetes.KUBE_UPGRADE_DOWNLOADING_IMAGES,
        )

        mock_get_active_controller = mock.MagicMock()
        p = mock.patch('sysinv.api.controllers.v1.utils.HostHelper.get_active_controller',
                       mock_get_active_controller)
        p.start().return_value = controller0
        self.addCleanup(p.stop)

        mock_kube_get_higher_equal_versions = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_get_higher_patch_version',
            mock_kube_get_higher_equal_versions)
        p.start().return_value = NEXT_VERSIONS
        self.addCleanup(p.stop)

        mock_disable_kubelet_garbage_collection = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.disable_kubelet_garbage_collection',
                       mock_disable_kubelet_garbage_collection)
        p.start()
        self.addCleanup(p.stop)

        mock_pmon_restart_service = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.pmon_restart_service', mock_pmon_restart_service)
        p.start()
        self.addCleanup(p.stop)

        mock_get_k8s_images = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.get_k8s_images', mock_get_k8s_images)
        p.start().return_value = {'fake_key': 'fake_image'}
        self.addCleanup(p.stop)

        mock_download_images_from_upstream_to_local_reg_and_crictl = mock.MagicMock()
        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager.'
            'download_images_from_upstream_to_local_reg_and_crictl',
            mock_download_images_from_upstream_to_local_reg_and_crictl)
        p.start().return_value = True
        self.addCleanup(p.stop)

        mock_pull_kubernetes_images = mock.MagicMock()
        p = mock.patch.object(
            agent_rpcapi.AgentAPI, 'pull_kubernetes_images', mock_pull_kubernetes_images)
        p.start().side_effect = Exception("Fake error")
        self.addCleanup(p.stop)

        # Pretend controller-0 is an active controller when kube_download_images is called
        self.service.host_uuid = controller0_host_uuid
        self.service.kube_download_images(self.context, TO_VERSION)

        mock_kube_get_higher_equal_versions.assert_called_once()
        mock_disable_kubelet_garbage_collection.assert_called_once()
        mock_pmon_restart_service.assert_called_once()
        self.assertEqual(mock_get_k8s_images.call_count, len(NEXT_VERSIONS))
        mock_download_images_from_upstream_to_local_reg_and_crictl.assert_called_with(
                                                                                FAKE_IMAGE_LIST)
        mock_pull_kubernetes_images.assert_called_once_with(
            self.context, controller1_host_uuid, FAKE_IMAGE_LIST)
        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state, kubernetes.KUBE_UPGRADE_DOWNLOADING_IMAGES_FAILED)

    def test_download_images_from_upstream_to_local_reg_and_crictl_success(self):
        """Test download_images_from_upstream_to_local_reg_and_crictl: success case
        """

        images_to_be_downloaded = ['fake_image1', 'fake_image2', 'fake_image3', 'fake_image4']
        fake_local_registry_auth = {'username': 'fake_username', 'password': 'fake_password'}
        fake_registries = {'fake_registries': 'fake_registries'}
        fake_crictl_auth = (
            f"{fake_local_registry_auth['username']}:{fake_local_registry_auth['password']}"
        )
        get_img_tag_with_registry_output = ('fake_target_image', fake_local_registry_auth)

        mock_get_local_docker_registry_auth = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.get_local_docker_registry_auth',
                       mock_get_local_docker_registry_auth)
        p.start().return_value = {'username': 'fake_username', 'password': 'fake_password'}
        self.addCleanup(p.stop)

        mock_retrieve_specified_registries = mock.MagicMock()
        p = mock.patch('sysinv.conductor.kube_app.DockerHelper.retrieve_specified_registries',
                       mock_retrieve_specified_registries)
        p.start().return_value = fake_registries
        self.addCleanup(p.stop)

        mock_get_crictl_image_list = mock.MagicMock()
        p = mock.patch('sysinv.common.containers.get_crictl_image_list',
                       mock_get_crictl_image_list)
        p.start().return_value = [f"{constants.DOCKER_REGISTRY_SERVER}/fake_image4",
                                  f"{constants.DOCKER_REGISTRY_SERVER}/fake_image5"]
        self.addCleanup(p.stop)

        mock_get_img_tag_with_registry = mock.MagicMock()
        p = mock.patch('sysinv.conductor.kube_app.DockerHelper._get_img_tag_with_registry',
                       mock_get_img_tag_with_registry)
        p.start().return_value = get_img_tag_with_registry_output
        self.addCleanup(p.stop)

        mock_docker_apiclient_pull = mock.MagicMock()
        p = mock.patch('docker.APIClient.pull', mock_docker_apiclient_pull)
        p.start()
        self.addCleanup(p.stop)

        mock_docker_apiclient_tag = mock.MagicMock()
        p = mock.patch('docker.APIClient.tag', mock_docker_apiclient_tag)
        p.start()
        self.addCleanup(p.stop)

        mock_docker_apiclient_push = mock.MagicMock()
        p = mock.patch('docker.APIClient.push', mock_docker_apiclient_push)
        p.start()
        self.addCleanup(p.stop)

        mock_docker_apiclient_inspect = mock.MagicMock()
        p = mock.patch('docker.APIClient.inspect_distribution', mock_docker_apiclient_inspect)
        p.start()
        self.addCleanup(p.stop)

        mock_docker_apiclient_remove_image = mock.MagicMock()
        p = mock.patch('docker.APIClient.remove_image', mock_docker_apiclient_remove_image)
        p.start()
        self.addCleanup(p.stop)

        mock_pull_image_to_crictl = mock.MagicMock()
        p = mock.patch('sysinv.common.containers.pull_image_to_crictl',
                       mock_pull_image_to_crictl)
        p.start()
        self.addCleanup(p.stop)

        result = self.service.download_images_from_upstream_to_local_reg_and_crictl(
            images_to_be_downloaded)

        # Assertions start here
        # Assert Main Result
        self.assertTrue(result)

        # Assert mock method calls
        mock_get_local_docker_registry_auth.assert_called_once()
        mock_retrieve_specified_registries.assert_called_once()
        mock_get_crictl_image_list.assert_called_once()

        expected_calls = [mock.call('fake_image1', fake_registries),
                          mock.call('fake_image2', fake_registries),
                          mock.call('fake_image3', fake_registries)]
        mock_get_img_tag_with_registry.assert_has_calls(expected_calls, any_order=True)

        mock_docker_apiclient_pull.assert_called_with(get_img_tag_with_registry_output[0],
                                                auth_config=get_img_tag_with_registry_output[1])
        self.assertEqual(mock_docker_apiclient_pull.call_count, 3)

        expected_calls = [mock.call(get_img_tag_with_registry_output[0],
                                    f"{constants.DOCKER_REGISTRY_SERVER}/fake_image1"),
                          mock.call(get_img_tag_with_registry_output[0],
                                    f"{constants.DOCKER_REGISTRY_SERVER}/fake_image2"),
                          mock.call(get_img_tag_with_registry_output[0],
                                    f"{constants.DOCKER_REGISTRY_SERVER}/fake_image3")]
        mock_docker_apiclient_tag.assert_has_calls(expected_calls, any_order=True)
        self.assertEqual(mock_docker_apiclient_tag.call_count, 3)

        expected_calls = [mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image1",
                                    auth_config=get_img_tag_with_registry_output[1]),
                          mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image2",
                                    auth_config=get_img_tag_with_registry_output[1]),
                          mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image3",
                                    auth_config=get_img_tag_with_registry_output[1])]
        mock_docker_apiclient_push.assert_has_calls(expected_calls, any_order=True)
        self.assertEqual(mock_docker_apiclient_push.call_count, 3)
        mock_docker_apiclient_inspect.assert_has_calls(expected_calls, any_order=True)
        self.assertEqual(mock_docker_apiclient_inspect.call_count, 3)

        expected_calls = [mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image1"),
                          mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image2"),
                          mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image3"),
                          mock.call("fake_target_image"),
                          mock.call("fake_target_image"),
                          mock.call("fake_target_image")]
        mock_docker_apiclient_remove_image.assert_has_calls(expected_calls, any_order=True)
        self.assertEqual(mock_docker_apiclient_remove_image.call_count, 6)

        expected_calls = [mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image1",
                                    fake_crictl_auth),
                          mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image2",
                                    fake_crictl_auth),
                          mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image3",
                                    fake_crictl_auth)]
        mock_pull_image_to_crictl.assert_has_calls(expected_calls, any_order=True)
        self.assertEqual(mock_pull_image_to_crictl.call_count, 3)

    def test_download_images_from_upstream_to_local_reg_and_crictl_failure_docker_pull_fail(self):
        """Test download_images_from_upstream_to_local_reg_and_crictl: docker pull failed

        Also tests failure to get list of existing images from crictl
        """
        images_to_be_downloaded = ['fake_image1', 'fake_image2', 'fake_image3']
        fake_local_registry_auth = {'username': 'fake_username', 'password': 'fake_password'}
        fake_registries = {'fake_registries': 'fake_registries'}
        get_img_tag_with_registry_output = ('fake_target_image', fake_local_registry_auth)

        mock_get_local_docker_registry_auth = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.get_local_docker_registry_auth',
                       mock_get_local_docker_registry_auth)
        p.start().return_value = {'username': 'fake_username', 'password': 'fake_password'}
        self.addCleanup(p.stop)

        mock_retrieve_specified_registries = mock.MagicMock()
        p = mock.patch('sysinv.conductor.kube_app.DockerHelper.retrieve_specified_registries',
                       mock_retrieve_specified_registries)
        p.start().return_value = fake_registries
        self.addCleanup(p.stop)

        mock_get_crictl_image_list = mock.MagicMock()
        p = mock.patch('sysinv.common.containers.get_crictl_image_list',
                       mock_get_crictl_image_list)
        p.start().side_effect = exception.SysinvException("Fake Error")
        self.addCleanup(p.stop)

        mock_get_img_tag_with_registry = mock.MagicMock()
        p = mock.patch('sysinv.conductor.kube_app.DockerHelper._get_img_tag_with_registry',
                       mock_get_img_tag_with_registry)
        p.start().return_value = get_img_tag_with_registry_output
        self.addCleanup(p.stop)

        mock_docker_apiclient_pull = mock.MagicMock()
        p = mock.patch('docker.APIClient.pull', mock_docker_apiclient_pull)
        p.start().side_effect = Exception("Fake pull error")
        self.addCleanup(p.stop)

        mock_docker_apiclient_tag = mock.MagicMock()
        p = mock.patch('docker.APIClient.tag', mock_docker_apiclient_tag)
        p.start()
        self.addCleanup(p.stop)

        mock_docker_apiclient_push = mock.MagicMock()
        p = mock.patch('docker.APIClient.push', mock_docker_apiclient_push)
        p.start()
        self.addCleanup(p.stop)

        mock_docker_apiclient_inspect = mock.MagicMock()
        p = mock.patch('docker.APIClient.inspect_distribution', mock_docker_apiclient_inspect)
        p.start()
        self.addCleanup(p.stop)

        mock_docker_apiclient_remove_image = mock.MagicMock()
        p = mock.patch('docker.APIClient.remove_image', mock_docker_apiclient_remove_image)
        p.start()
        self.addCleanup(p.stop)

        mock_pull_image_to_crictl = mock.MagicMock()
        p = mock.patch('sysinv.common.containers.pull_image_to_crictl',
                       mock_pull_image_to_crictl)
        p.start()
        self.addCleanup(p.stop)

        result = self.service.download_images_from_upstream_to_local_reg_and_crictl(
            images_to_be_downloaded)

        # Assertions start here
        # Assert Main Result
        self.assertFalse(result)

        # Assert mock method calls
        mock_get_local_docker_registry_auth.assert_called_once()
        mock_retrieve_specified_registries.assert_called_once()
        mock_get_crictl_image_list.assert_called_once()

        # Assert Retries
        self.assertEqual(mock_get_img_tag_with_registry.call_count,
                         5 * len(images_to_be_downloaded))
        self.assertEqual(mock_docker_apiclient_pull.call_count, 5 * len(images_to_be_downloaded))

        mock_docker_apiclient_tag.assert_not_called()
        mock_docker_apiclient_push.assert_not_called()
        mock_docker_apiclient_inspect.assert_not_called()
        mock_docker_apiclient_remove_image.assert_not_called()
        mock_pull_image_to_crictl.assert_not_called()

    def test_download_images_from_upstream_to_local_reg_and_crictl_failure_docker_push_fail(self):
        """Test download_images_from_upstream_to_local_reg_and_crictl: docker push failed

        """
        images_to_be_downloaded = ['fake_image1', 'fake_image2', 'fake_image3']
        fake_local_registry_auth = {'username': 'fake_username', 'password': 'fake_password'}
        fake_registries = {'fake_registries': 'fake_registries'}
        get_img_tag_with_registry_output = ('fake_target_image', fake_local_registry_auth)

        mock_get_local_docker_registry_auth = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.get_local_docker_registry_auth',
                       mock_get_local_docker_registry_auth)
        p.start().return_value = {'username': 'fake_username', 'password': 'fake_password'}
        self.addCleanup(p.stop)

        mock_retrieve_specified_registries = mock.MagicMock()
        p = mock.patch('sysinv.conductor.kube_app.DockerHelper.retrieve_specified_registries',
                       mock_retrieve_specified_registries)
        p.start().return_value = fake_registries
        self.addCleanup(p.stop)

        mock_get_crictl_image_list = mock.MagicMock()
        p = mock.patch('sysinv.common.containers.get_crictl_image_list',
                       mock_get_crictl_image_list)
        p.start().side_effect = exception.SysinvException("Fake Error")
        self.addCleanup(p.stop)

        mock_get_img_tag_with_registry = mock.MagicMock()
        p = mock.patch('sysinv.conductor.kube_app.DockerHelper._get_img_tag_with_registry',
                       mock_get_img_tag_with_registry)
        p.start().return_value = get_img_tag_with_registry_output
        self.addCleanup(p.stop)

        mock_docker_apiclient_pull = mock.MagicMock()
        p = mock.patch('docker.APIClient.pull', mock_docker_apiclient_pull)
        p.start()
        self.addCleanup(p.stop)

        mock_docker_apiclient_tag = mock.MagicMock()
        p = mock.patch('docker.APIClient.tag', mock_docker_apiclient_tag)
        p.start()
        self.addCleanup(p.stop)

        mock_docker_apiclient_push = mock.MagicMock()
        p = mock.patch('docker.APIClient.push', mock_docker_apiclient_push)
        p.start().side_effect = Exception("Fake push exception")
        self.addCleanup(p.stop)

        mock_docker_apiclient_inspect = mock.MagicMock()
        p = mock.patch('docker.APIClient.inspect_distribution', mock_docker_apiclient_inspect)
        p.start()
        self.addCleanup(p.stop)

        mock_docker_apiclient_remove_image = mock.MagicMock()
        p = mock.patch('docker.APIClient.remove_image', mock_docker_apiclient_remove_image)
        p.start()
        self.addCleanup(p.stop)

        mock_pull_image_to_crictl = mock.MagicMock()
        p = mock.patch('sysinv.common.containers.pull_image_to_crictl',
                       mock_pull_image_to_crictl)
        p.start()
        self.addCleanup(p.stop)

        result = self.service.download_images_from_upstream_to_local_reg_and_crictl(
            images_to_be_downloaded)

        # Assertions start here
        # Assert Main Result
        self.assertFalse(result)

        # Assert mock method calls
        mock_get_local_docker_registry_auth.assert_called_once()
        mock_retrieve_specified_registries.assert_called_once()
        mock_get_crictl_image_list.assert_called_once()

        expected_calls = [mock.call('fake_image1', fake_registries),
                          mock.call('fake_image2', fake_registries),
                          mock.call('fake_image3', fake_registries)]
        mock_get_img_tag_with_registry.assert_has_calls(expected_calls, any_order=True)

        mock_docker_apiclient_pull.assert_called_with(get_img_tag_with_registry_output[0],
                                                auth_config=get_img_tag_with_registry_output[1])
        self.assertEqual(mock_docker_apiclient_pull.call_count, 3)

        expected_calls = [mock.call(get_img_tag_with_registry_output[0],
                                    f"{constants.DOCKER_REGISTRY_SERVER}/fake_image1"),
                          mock.call(get_img_tag_with_registry_output[0],
                                    f"{constants.DOCKER_REGISTRY_SERVER}/fake_image2"),
                          mock.call(get_img_tag_with_registry_output[0],
                                    f"{constants.DOCKER_REGISTRY_SERVER}/fake_image3")]
        mock_docker_apiclient_tag.assert_has_calls(expected_calls, any_order=True)
        self.assertEqual(mock_docker_apiclient_tag.call_count, 3)

        mock_docker_apiclient_push.assert_called()

        mock_docker_apiclient_inspect.assert_not_called()
        mock_docker_apiclient_remove_image.assert_not_called()
        mock_pull_image_to_crictl.assert_not_called()

    def test_download_images_from_upstream_to_local_reg_and_crictl_success_docker_remove_image_failed(self):  # pylint: disable=line-too-long # noqa: E501
        """Test download_images_from_upstream_to_local_reg_and_crictl: Docker remove image failed

        """
        images_to_be_downloaded = ['fake_image1', 'fake_image2', 'fake_image3']
        fake_local_registry_auth = {'username': 'fake_username', 'password': 'fake_password'}
        fake_registries = {'fake_registries': 'fake_registries'}
        fake_crictl_auth = (
            f"{fake_local_registry_auth['username']}:{fake_local_registry_auth['password']}"
        )
        get_img_tag_with_registry_output = ('fake_target_image', fake_local_registry_auth)

        mock_get_local_docker_registry_auth = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.get_local_docker_registry_auth',
                       mock_get_local_docker_registry_auth)
        p.start().return_value = {'username': 'fake_username', 'password': 'fake_password'}
        self.addCleanup(p.stop)

        mock_retrieve_specified_registries = mock.MagicMock()
        p = mock.patch('sysinv.conductor.kube_app.DockerHelper.retrieve_specified_registries',
                       mock_retrieve_specified_registries)
        p.start().return_value = fake_registries
        self.addCleanup(p.stop)

        mock_get_crictl_image_list = mock.MagicMock()
        p = mock.patch('sysinv.common.containers.get_crictl_image_list',
                       mock_get_crictl_image_list)
        p.start().side_effect = exception.SysinvException("Fake Error")
        self.addCleanup(p.stop)

        mock_get_img_tag_with_registry = mock.MagicMock()
        p = mock.patch('sysinv.conductor.kube_app.DockerHelper._get_img_tag_with_registry',
                       mock_get_img_tag_with_registry)
        p.start().return_value = get_img_tag_with_registry_output
        self.addCleanup(p.stop)

        mock_docker_apiclient_pull = mock.MagicMock()
        p = mock.patch('docker.APIClient.pull', mock_docker_apiclient_pull)
        p.start()
        self.addCleanup(p.stop)

        mock_docker_apiclient_tag = mock.MagicMock()
        p = mock.patch('docker.APIClient.tag', mock_docker_apiclient_tag)
        p.start()
        self.addCleanup(p.stop)

        mock_docker_apiclient_push = mock.MagicMock()
        p = mock.patch('docker.APIClient.push', mock_docker_apiclient_push)
        p.start()
        self.addCleanup(p.stop)

        mock_docker_apiclient_inspect = mock.MagicMock()
        p = mock.patch('docker.APIClient.inspect_distribution', mock_docker_apiclient_inspect)
        p.start()
        self.addCleanup(p.stop)

        mock_docker_apiclient_remove_image = mock.MagicMock()
        p = mock.patch('docker.APIClient.remove_image', mock_docker_apiclient_remove_image)
        p.start().side_effect = Exception("Fake error")
        self.addCleanup(p.stop)

        mock_pull_image_to_crictl = mock.MagicMock()
        p = mock.patch('sysinv.common.containers.pull_image_to_crictl',
                       mock_pull_image_to_crictl)
        p.start()
        self.addCleanup(p.stop)

        result = self.service.download_images_from_upstream_to_local_reg_and_crictl(
            images_to_be_downloaded)

        # Assertions start here
        # Assert Main Result
        self.assertTrue(result)

        # Assert mock method calls
        mock_get_local_docker_registry_auth.assert_called_once()
        mock_retrieve_specified_registries.assert_called_once()
        mock_get_crictl_image_list.assert_called_once()

        expected_calls = [mock.call('fake_image1', fake_registries),
                          mock.call('fake_image2', fake_registries),
                          mock.call('fake_image3', fake_registries)]
        mock_get_img_tag_with_registry.assert_has_calls(expected_calls, any_order=True)

        mock_docker_apiclient_pull.assert_called_with(get_img_tag_with_registry_output[0],
                                                auth_config=get_img_tag_with_registry_output[1])
        self.assertEqual(mock_docker_apiclient_pull.call_count, 3)

        expected_calls = [mock.call(get_img_tag_with_registry_output[0],
                                    f"{constants.DOCKER_REGISTRY_SERVER}/fake_image1"),
                          mock.call(get_img_tag_with_registry_output[0],
                                    f"{constants.DOCKER_REGISTRY_SERVER}/fake_image2"),
                          mock.call(get_img_tag_with_registry_output[0],
                                    f"{constants.DOCKER_REGISTRY_SERVER}/fake_image3")]
        mock_docker_apiclient_tag.assert_has_calls(expected_calls, any_order=True)
        self.assertEqual(mock_docker_apiclient_tag.call_count, 3)

        expected_calls = [mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image1",
                                    auth_config=get_img_tag_with_registry_output[1]),
                          mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image2",
                                    auth_config=get_img_tag_with_registry_output[1]),
                          mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image3",
                                    auth_config=get_img_tag_with_registry_output[1])]
        mock_docker_apiclient_push.assert_has_calls(expected_calls, any_order=True)
        self.assertEqual(mock_docker_apiclient_push.call_count, 3)
        mock_docker_apiclient_inspect.assert_has_calls(expected_calls, any_order=True)
        self.assertEqual(mock_docker_apiclient_inspect.call_count, 3)

        mock_docker_apiclient_remove_image.assert_called()

        expected_calls = [mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image1",
                                    fake_crictl_auth),
                          mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image2",
                                    fake_crictl_auth),
                          mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image3",
                                    fake_crictl_auth)]
        mock_pull_image_to_crictl.assert_has_calls(expected_calls, any_order=True)
        self.assertEqual(mock_pull_image_to_crictl.call_count, 3)

    def test_download_images_from_upstream_to_local_reg_and_crictl_failure_crictl_pull_failed(self):
        """Test download_images_from_upstream_to_local_reg_and_crictl: Crictl pull failed

        """
        images_to_be_downloaded = ['fake_image1', 'fake_image2', 'fake_image3']
        fake_local_registry_auth = {'username': 'fake_username', 'password': 'fake_password'}
        fake_registries = {'fake_registries': 'fake_registries'}
        get_img_tag_with_registry_output = ('fake_target_image', fake_local_registry_auth)

        mock_get_local_docker_registry_auth = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.get_local_docker_registry_auth',
                       mock_get_local_docker_registry_auth)
        p.start().return_value = {'username': 'fake_username', 'password': 'fake_password'}
        self.addCleanup(p.stop)

        mock_retrieve_specified_registries = mock.MagicMock()
        p = mock.patch('sysinv.conductor.kube_app.DockerHelper.retrieve_specified_registries',
                       mock_retrieve_specified_registries)
        p.start().return_value = fake_registries
        self.addCleanup(p.stop)

        mock_get_crictl_image_list = mock.MagicMock()
        p = mock.patch('sysinv.common.containers.get_crictl_image_list',
                       mock_get_crictl_image_list)
        p.start().side_effect = exception.SysinvException("Fake Error")
        self.addCleanup(p.stop)

        mock_get_img_tag_with_registry = mock.MagicMock()
        p = mock.patch('sysinv.conductor.kube_app.DockerHelper._get_img_tag_with_registry',
                       mock_get_img_tag_with_registry)
        p.start().return_value = get_img_tag_with_registry_output
        self.addCleanup(p.stop)

        mock_docker_apiclient_pull = mock.MagicMock()
        p = mock.patch('docker.APIClient.pull', mock_docker_apiclient_pull)
        p.start()
        self.addCleanup(p.stop)

        mock_docker_apiclient_tag = mock.MagicMock()
        p = mock.patch('docker.APIClient.tag', mock_docker_apiclient_tag)
        p.start()
        self.addCleanup(p.stop)

        mock_docker_apiclient_push = mock.MagicMock()
        p = mock.patch('docker.APIClient.push', mock_docker_apiclient_push)
        p.start()
        self.addCleanup(p.stop)

        mock_docker_apiclient_inspect = mock.MagicMock()
        p = mock.patch('docker.APIClient.inspect_distribution', mock_docker_apiclient_inspect)
        p.start()
        self.addCleanup(p.stop)

        mock_docker_apiclient_remove_image = mock.MagicMock()
        p = mock.patch('docker.APIClient.remove_image', mock_docker_apiclient_remove_image)
        p.start()
        self.addCleanup(p.stop)

        mock_pull_image_to_crictl = mock.MagicMock()
        p = mock.patch('sysinv.common.containers.pull_image_to_crictl',
                       mock_pull_image_to_crictl)
        p.start().side_effect = exception.SysinvException("Fake crictl pull error")
        self.addCleanup(p.stop)

        result = self.service.download_images_from_upstream_to_local_reg_and_crictl(
            images_to_be_downloaded)

        # Assertions start here
        # Assert Main Result
        self.assertFalse(result)

        # Assert mock method calls
        mock_get_local_docker_registry_auth.assert_called_once()
        mock_retrieve_specified_registries.assert_called_once()
        mock_get_crictl_image_list.assert_called_once()

        expected_calls = [mock.call('fake_image1', fake_registries),
                          mock.call('fake_image2', fake_registries),
                          mock.call('fake_image3', fake_registries)]
        mock_get_img_tag_with_registry.assert_has_calls(expected_calls, any_order=True)

        mock_docker_apiclient_pull.assert_called_with(get_img_tag_with_registry_output[0],
                                                auth_config=get_img_tag_with_registry_output[1])
        self.assertEqual(mock_docker_apiclient_pull.call_count, 3)

        expected_calls = [mock.call(get_img_tag_with_registry_output[0],
                                    f"{constants.DOCKER_REGISTRY_SERVER}/fake_image1"),
                          mock.call(get_img_tag_with_registry_output[0],
                                    f"{constants.DOCKER_REGISTRY_SERVER}/fake_image2"),
                          mock.call(get_img_tag_with_registry_output[0],
                                    f"{constants.DOCKER_REGISTRY_SERVER}/fake_image3")]
        mock_docker_apiclient_tag.assert_has_calls(expected_calls, any_order=True)
        self.assertEqual(mock_docker_apiclient_tag.call_count, 3)

        expected_calls = [mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image1",
                                    auth_config=get_img_tag_with_registry_output[1]),
                          mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image2",
                                    auth_config=get_img_tag_with_registry_output[1]),
                          mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image3",
                                    auth_config=get_img_tag_with_registry_output[1])]
        mock_docker_apiclient_push.assert_has_calls(expected_calls, any_order=True)
        self.assertEqual(mock_docker_apiclient_push.call_count, 3)
        mock_docker_apiclient_inspect.assert_has_calls(expected_calls, any_order=True)
        self.assertEqual(mock_docker_apiclient_inspect.call_count, 3)

        expected_calls = [mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image1"),
                          mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image2"),
                          mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image3"),
                          mock.call("fake_target_image"),
                          mock.call("fake_target_image"),
                          mock.call("fake_target_image")]
        mock_docker_apiclient_remove_image.assert_has_calls(expected_calls, any_order=True)
        self.assertEqual(mock_docker_apiclient_remove_image.call_count, 6)
        mock_pull_image_to_crictl.assert_called()

    # def test_kube_host_cordon(self):
    #     system_dict = self.system.as_dict()
    #     system_dict['system_mode'] = constants.SYSTEM_MODE_SIMPLEX
    #     self.dbapi.isystem_update(self.system.uuid, system_dict)

    #     # Create controller-0
    #     config_uuid = str(uuid.uuid4())
    #     self._create_test_ihost(
    #         personality=constants.CONTROLLER,
    #         hostname='controller-0',
    #         uuid=str(uuid.uuid4()),
    #         config_status=None,
    #         config_applied=config_uuid,
    #         config_target=config_uuid,
    #         invprovision=constants.PROVISIONED,
    #         administrative=constants.ADMIN_UNLOCKED,
    #         operational=constants.OPERATIONAL_ENABLED,
    #         availability=constants.AVAILABILITY_ONLINE,
    #     )
    #     # Create an upgrade
    #     utils.create_test_kube_upgrade(
    #         from_version='v1.42.1',
    #         to_version='v1.42.2',
    #         state=kubernetes.KUBE_UPGRADE_CORDON,
    #     )

    #     self.fake_subprocess_popen.returncode = 0

    #     # Cordon node
    #     self.service.kube_host_cordon(self.context, constants.CONTROLLER_0_HOSTNAME)

    #     # Verify that we called kubectl drain command to cordon
    #     cordon_cmd = ['kubectl', '--kubeconfig=%s' % kubernetes.KUBERNETES_ADMIN_CONF,
    #                   'drain', constants.CONTROLLER_0_HOSTNAME, '--ignore-daemonsets',
    #                   '--delete-emptydir-data', '--force',
    #                   '--skip-wait-for-delete-timeout=1', '--timeout=150s']
    #     self.mock_subprocess_popen.assert_called_with(cordon_cmd, stdout=-1, stderr=-1,
    #                                                   universal_newlines=True)

    #     # Verify that the upgrade state was updated
    #     updated_upgrade = self.dbapi.kube_upgrade_get_one()
    #     self.assertEqual(updated_upgrade.state,
    #                      kubernetes.KUBE_UPGRADE_CORDON_COMPLETE)

    def test_get_kubernetes_system_images_success(self):
        """Test successful execution of _get_kubernetes_system_images
        """
        fake_images_path = "/fake/path"
        fake_file_object = io.TextIOWrapper(io.BytesIO())
        expected_images = {'fake_key1': 'fake_image1', 'fake_key2': 'fake_image2'}

        mock_os_path_join = mock.MagicMock()
        p = mock.patch('os.path.join', mock_os_path_join)
        p.start().return_value = fake_images_path
        self.addCleanup(p.stop)

        mock_open = mock.MagicMock()
        p = mock.patch('builtins.open', mock_open)
        p.start().return_value = fake_file_object
        self.addCleanup(p.stop)

        mock_ruamel_yaml = mock.MagicMock()
        p = mock.patch('ruamel.yaml.safe_load', mock_ruamel_yaml)
        p.start().return_value = expected_images
        self.addCleanup(p.stop)

        actual_images = self.service._get_kubernetes_system_images("fake kube version")

        self.assertEqual(expected_images, actual_images)

        mock_os_path_join.assert_called_once()
        mock_open.assert_called_once_with(fake_images_path, 'r')
        mock_ruamel_yaml.assert_called_once_with(fake_file_object)

    def test_get_kubernetes_system_images_empty_images(self):
        """Test failed execution of _get_kubernetes_system_images
        """
        fake_images_path = "/fake/path"
        fake_file_object = io.TextIOWrapper(io.BytesIO())

        mock_os_path_join = mock.MagicMock()
        p = mock.patch('os.path.join', mock_os_path_join)
        p.start().return_value = fake_images_path
        self.addCleanup(p.stop)

        mock_open = mock.MagicMock()
        p = mock.patch('builtins.open', mock_open)
        p.start().return_value = fake_file_object
        self.addCleanup(p.stop)

        mock_ruamel_yaml = mock.MagicMock()
        p = mock.patch('ruamel.yaml.safe_load', mock_ruamel_yaml)
        p.start().return_value = {}
        self.addCleanup(p.stop)

        self.assertRaises(exception.SysinvException,
                          self.service._get_kubernetes_system_images,
                          "fake kube version")

        mock_os_path_join.assert_called_once()
        mock_open.assert_called_once_with(fake_images_path, 'r')
        mock_ruamel_yaml.assert_called_once_with(fake_file_object)

    def test_get_kubernetes_system_images_failure(self):
        """Test failed execution of _get_kubernetes_system_images
        """
        fake_images_path = "/fake/path"
        fake_file_object = io.TextIOWrapper(io.BytesIO())

        mock_os_path_join = mock.MagicMock()
        p = mock.patch('os.path.join', mock_os_path_join)
        p.start().return_value = fake_images_path
        self.addCleanup(p.stop)

        mock_open = mock.MagicMock()
        p = mock.patch('builtins.open', mock_open)
        p.start().return_value = fake_file_object
        self.addCleanup(p.stop)

        mock_ruamel_yaml = mock.MagicMock()
        p = mock.patch('ruamel.yaml.safe_load', mock_ruamel_yaml)
        p.start().side_effect = Exception("Fake error")
        self.addCleanup(p.stop)

        self.assertRaises(exception.SysinvException,
                          self.service._get_kubernetes_system_images,
                          "fake kube version")

        mock_os_path_join.assert_called_once()
        mock_open.assert_called_once_with(fake_images_path, 'r')
        mock_ruamel_yaml.assert_called_once_with(fake_file_object)

    def test_kube_upgrade_networking_success_ipv4(self):
        """Test successful execution of kubernetes networking upgrade (ipv4)
        """
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        FROM_VERSION = 'v1.29.2'
        TO_VERSION = 'v1.30.6'
        network_images = {'calico_cni_img': 'fake_calico_cni_img',
                           'calico_node_img': 'fake_calico_node_img',
                           'calico_kube_controllers_img': 'fake_calico_kube_controllers_img',
                           'multus_img': 'fake_multus_img',
                           'sriov_cni_img': 'fake_sriov_cni_img',
                           'sriov_network_device_img': 'fake_sriov_network_device_img'}
        image_download_result = True
        upgrade_overrides_file_exists = True
        upgrade_overrides = {"cluster_pod_subnet": "172.16.0.0/16",
                             "cluster_host_floating_address": "192.168.206.1",
                             "cluster_host_node_0_address": "192.168.206.2"}

        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version=FROM_VERSION,
            to_version=TO_VERSION,
            state=kubernetes.KUBE_UPGRADING_NETWORKING,
        )

        mock_sanitize_kubeadm_configmap = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.sanitize_kubeadm_configmap',
                       mock_sanitize_kubeadm_configmap)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_backup_kube_control_plane = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.backup_kube_control_plane',
                       mock_backup_kube_control_plane)
        p.start()
        self.addCleanup(p.stop)

        mock_get_kubernetes_system_images = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager._get_kubernetes_system_images',
                       mock_get_kubernetes_system_images)
        p.start().return_value = network_images
        self.addCleanup(p.stop)

        mock_download_images_from_upstream_to_local_reg_and_crictl = mock.MagicMock()
        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager.'
            'download_images_from_upstream_to_local_reg_and_crictl',
            mock_download_images_from_upstream_to_local_reg_and_crictl)
        p.start().return_value = image_download_result
        self.addCleanup(p.stop)

        mock_utils_execute = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.execute', mock_utils_execute)
        p.start()
        self.addCleanup(p.stop)

        mock_os_path_exists = mock.MagicMock()
        p = mock.patch('os.path.exists', mock_os_path_exists)
        p.start().return_value = upgrade_overrides_file_exists
        self.addCleanup(p.stop)

        mock_open = mock.mock_open()
        p = mock.patch('builtins.open', mock_open)
        p.start()
        self.addCleanup(p.stop)

        mock_ruamel_yaml_safe_load = mock.MagicMock()
        p = mock.patch('ruamel.yaml.safe_load', mock_ruamel_yaml_safe_load)
        p.start().return_value = upgrade_overrides
        self.addCleanup(p.stop)

        mock_shutil_copy2 = mock.MagicMock()
        p = mock.patch('shutil.copy2', mock_shutil_copy2)
        p.start()
        self.addCleanup(p.stop)

        mock_render_jinja_template_from_file = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.render_jinja_template_from_file',
                       mock_render_jinja_template_from_file)
        p.start().return_value = "fake_rendered_string"
        self.addCleanup(p.stop)

        mock_kubectl_apply = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.kubectl_apply', mock_kubectl_apply)
        p.start()
        self.addCleanup(p.stop)

        mock_os_remove = mock.MagicMock()
        p = mock.patch('os.remove', mock_os_remove)
        p.start()
        self.addCleanup(p.stop)

        self.service.kube_upgrade_networking(self.context, TO_VERSION)

        mock_sanitize_kubeadm_configmap.assert_called_once()
        mock_backup_kube_control_plane.assert_called_once()
        mock_get_kubernetes_system_images.assert_called_once_with(TO_VERSION)
        mock_download_images_from_upstream_to_local_reg_and_crictl.assert_called_once()
        mock_utils_execute.assert_called()
        mock_os_path_exists.assert_called()
        mock_open.assert_called()
        mock_ruamel_yaml_safe_load.assert_called_once()
        mock_shutil_copy2.assert_called_once()

        mock_render_jinja_template_from_file.assert_called()
        self.assertEqual(mock_render_jinja_template_from_file.call_count, 4)

        expected_apply_calls = [mock.call(os.path.join(kubernetes.KUBERNETES_CONF_DIR,
                                                       'update_coredns.yaml')),
                                mock.call(os.path.join(kubernetes.KUBERNETES_CONF_DIR,
                                                       'update_calico.yaml')),
                                mock.call(os.path.join(kubernetes.KUBERNETES_CONF_DIR,
                                                       'update_multus.yaml')),
                                mock.call(os.path.join(kubernetes.KUBERNETES_CONF_DIR,
                                                       'update_sriov-cni.yaml')),
                                mock.call(os.path.join(kubernetes.KUBERNETES_CONF_DIR,
                                                       'update_sriovdp-daemonset.yaml'))]
        mock_kubectl_apply.assert_has_calls(expected_apply_calls)
        self.assertEqual(mock_kubectl_apply.call_count, 5)

        mock_os_remove.assert_called_once()

        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state, kubernetes.KUBE_UPGRADED_NETWORKING)

    def test_kube_upgrade_networking_success_ipv6(self):
        """Test successful execution of kubernetes networking upgrade (ipv6)
        """
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        FROM_VERSION = 'v1.29.2'
        TO_VERSION = 'v1.30.6'
        network_images = {'calico_cni_img': 'fake_calico_cni_img',
                           'calico_node_img': 'fake_calico_node_img',
                           'calico_kube_controllers_img': 'fake_calico_kube_controllers_img',
                           'multus_img': 'fake_multus_img',
                           'sriov_cni_img': 'fake_sriov_cni_img',
                           'sriov_network_device_img': 'fake_sriov_network_device_img'}
        image_download_result = True
        upgrade_overrides_file_exists = True
        upgrade_overrides = {"cluster_pod_subnet": "::ffff:ac10:0/16",
                             "cluster_host_floating_address": "::ffff:c0a8:ce01",
                             "cluster_host_node_0_address": "::ffff:c0a8:ce02"}

        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version=FROM_VERSION,
            to_version=TO_VERSION,
            state=kubernetes.KUBE_UPGRADING_NETWORKING,
        )

        mock_sanitize_kubeadm_configmap = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.sanitize_kubeadm_configmap',
                       mock_sanitize_kubeadm_configmap)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_backup_kube_control_plane = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.backup_kube_control_plane',
                       mock_backup_kube_control_plane)
        p.start()
        self.addCleanup(p.stop)

        mock_get_kubernetes_system_images = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager._get_kubernetes_system_images',
                       mock_get_kubernetes_system_images)
        p.start().return_value = network_images
        self.addCleanup(p.stop)

        mock_download_images_from_upstream_to_local_reg_and_crictl = mock.MagicMock()
        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager.'
            'download_images_from_upstream_to_local_reg_and_crictl',
            mock_download_images_from_upstream_to_local_reg_and_crictl)
        p.start().return_value = image_download_result
        self.addCleanup(p.stop)

        mock_utils_execute = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.execute', mock_utils_execute)
        p.start()
        self.addCleanup(p.stop)

        mock_os_path_exists = mock.MagicMock()
        p = mock.patch('os.path.exists', mock_os_path_exists)
        p.start().return_value = upgrade_overrides_file_exists
        self.addCleanup(p.stop)

        mock_open = mock.mock_open()
        p = mock.patch('builtins.open', mock_open)
        p.start()
        self.addCleanup(p.stop)

        mock_ruamel_yaml_safe_load = mock.MagicMock()
        p = mock.patch('ruamel.yaml.safe_load', mock_ruamel_yaml_safe_load)
        p.start().return_value = upgrade_overrides
        self.addCleanup(p.stop)

        mock_shutil_copy2 = mock.MagicMock()
        p = mock.patch('shutil.copy2', mock_shutil_copy2)
        p.start()
        self.addCleanup(p.stop)

        mock_render_jinja_template_from_file = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.render_jinja_template_from_file',
                       mock_render_jinja_template_from_file)
        p.start().return_value = "fake_rendered_string"
        self.addCleanup(p.stop)

        mock_kubectl_apply = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.kubectl_apply', mock_kubectl_apply)
        p.start()
        self.addCleanup(p.stop)

        mock_os_remove = mock.MagicMock()
        p = mock.patch('os.remove', mock_os_remove)
        p.start()
        self.addCleanup(p.stop)

        self.service.kube_upgrade_networking(self.context, TO_VERSION)

        mock_sanitize_kubeadm_configmap.assert_called_once()
        mock_backup_kube_control_plane.assert_called_once()
        mock_get_kubernetes_system_images.assert_called_once_with(TO_VERSION)
        mock_download_images_from_upstream_to_local_reg_and_crictl.assert_called_once()
        mock_utils_execute.assert_called()
        mock_os_path_exists.assert_called()
        mock_open.assert_called()
        mock_ruamel_yaml_safe_load.assert_called_once()
        mock_shutil_copy2.assert_called_once()

        mock_render_jinja_template_from_file.assert_called()
        self.assertEqual(mock_render_jinja_template_from_file.call_count, 4)

        expected_apply_calls = [mock.call(os.path.join(kubernetes.KUBERNETES_CONF_DIR,
                                                       'update_coredns.yaml')),
                                mock.call(os.path.join(kubernetes.KUBERNETES_CONF_DIR,
                                                       'update_calico.yaml')),
                                mock.call(os.path.join(kubernetes.KUBERNETES_CONF_DIR,
                                                       'update_multus.yaml')),
                                mock.call(os.path.join(kubernetes.KUBERNETES_CONF_DIR,
                                                       'update_sriov-cni.yaml')),
                                mock.call(os.path.join(kubernetes.KUBERNETES_CONF_DIR,
                                                       'update_sriovdp-daemonset.yaml'))]
        mock_kubectl_apply.assert_has_calls(expected_apply_calls)
        self.assertEqual(mock_kubectl_apply.call_count, 5)

        mock_os_remove.assert_called_once()

        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state, kubernetes.KUBE_UPGRADED_NETWORKING)

    def test_kube_upgrade_networking_success_multiple_ip_addresses(self):
        """Test successful execution of kubernetes networking upgrade (multiple IP addresses)
        """
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        FROM_VERSION = 'v1.29.2'
        TO_VERSION = 'v1.30.6'
        network_images = {'calico_cni_img': 'fake_calico_cni_img',
                           'calico_node_img': 'fake_calico_node_img',
                           'calico_kube_controllers_img': 'fake_calico_kube_controllers_img',
                           'multus_img': 'fake_multus_img',
                           'sriov_cni_img': 'fake_sriov_cni_img',
                           'sriov_network_device_img': 'fake_sriov_network_device_img'}
        image_download_result = True
        upgrade_overrides_file_exists = True
        upgrade_overrides = {"cluster_pod_subnet": "172.16.0.0/16",
                             "cluster_host_floating_address": "192.168.206.1,192.168.206.2",
                             "cluster_host_node_0_address": "192.168.206.3,192.168.206.4"}

        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version=FROM_VERSION,
            to_version=TO_VERSION,
            state=kubernetes.KUBE_UPGRADING_NETWORKING,
        )

        mock_sanitize_kubeadm_configmap = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.sanitize_kubeadm_configmap',
                       mock_sanitize_kubeadm_configmap)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_backup_kube_control_plane = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.backup_kube_control_plane',
                       mock_backup_kube_control_plane)
        p.start()
        self.addCleanup(p.stop)

        mock_get_kubernetes_system_images = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager._get_kubernetes_system_images',
                       mock_get_kubernetes_system_images)
        p.start().return_value = network_images
        self.addCleanup(p.stop)

        mock_download_images_from_upstream_to_local_reg_and_crictl = mock.MagicMock()
        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager.'
            'download_images_from_upstream_to_local_reg_and_crictl',
            mock_download_images_from_upstream_to_local_reg_and_crictl)
        p.start().return_value = image_download_result
        self.addCleanup(p.stop)

        mock_utils_execute = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.execute', mock_utils_execute)
        p.start()
        self.addCleanup(p.stop)

        mock_os_path_exists = mock.MagicMock()
        p = mock.patch('os.path.exists', mock_os_path_exists)
        p.start().return_value = upgrade_overrides_file_exists
        self.addCleanup(p.stop)

        mock_open = mock.mock_open()
        p = mock.patch('builtins.open', mock_open)
        p.start()
        self.addCleanup(p.stop)

        mock_ruamel_yaml_safe_load = mock.MagicMock()
        p = mock.patch('ruamel.yaml.safe_load', mock_ruamel_yaml_safe_load)
        p.start().return_value = upgrade_overrides
        self.addCleanup(p.stop)

        mock_shutil_copy2 = mock.MagicMock()
        p = mock.patch('shutil.copy2', mock_shutil_copy2)
        p.start()
        self.addCleanup(p.stop)

        mock_render_jinja_template_from_file = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.render_jinja_template_from_file',
                       mock_render_jinja_template_from_file)
        p.start().return_value = "fake_rendered_string"
        self.addCleanup(p.stop)

        mock_kubectl_apply = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.kubectl_apply', mock_kubectl_apply)
        p.start()
        self.addCleanup(p.stop)

        mock_os_remove = mock.MagicMock()
        p = mock.patch('os.remove', mock_os_remove)
        p.start()
        self.addCleanup(p.stop)

        self.service.kube_upgrade_networking(self.context, TO_VERSION)

        mock_sanitize_kubeadm_configmap.assert_called_once()
        mock_backup_kube_control_plane.assert_called_once()
        mock_get_kubernetes_system_images.assert_called_once_with(TO_VERSION)
        mock_download_images_from_upstream_to_local_reg_and_crictl.assert_called_once()
        mock_utils_execute.assert_called()
        mock_os_path_exists.assert_called()
        mock_open.assert_called()
        mock_ruamel_yaml_safe_load.assert_called_once()
        mock_shutil_copy2.assert_called_once()

        mock_render_jinja_template_from_file.assert_called()
        self.assertEqual(mock_render_jinja_template_from_file.call_count, 4)

        expected_apply_calls = [mock.call(os.path.join(kubernetes.KUBERNETES_CONF_DIR,
                                                       'update_coredns.yaml')),
                                mock.call(os.path.join(kubernetes.KUBERNETES_CONF_DIR,
                                                       'update_calico.yaml')),
                                mock.call(os.path.join(kubernetes.KUBERNETES_CONF_DIR,
                                                       'update_multus.yaml')),
                                mock.call(os.path.join(kubernetes.KUBERNETES_CONF_DIR,
                                                       'update_sriov-cni.yaml')),
                                mock.call(os.path.join(kubernetes.KUBERNETES_CONF_DIR,
                                                       'update_sriovdp-daemonset.yaml'))]
        mock_kubectl_apply.assert_has_calls(expected_apply_calls)
        self.assertEqual(mock_kubectl_apply.call_count, 5)

        mock_os_remove.assert_called_once()

        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state, kubernetes.KUBE_UPGRADED_NETWORKING)

    def test_kube_upgrade_networking_failure_sanitize_feature_gates_failed(self):
        """Test failed execution of kubernetes networking upgrade (sanitize_feature_gates_failed)
        """
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        FROM_VERSION = 'v1.29.2'
        TO_VERSION = 'v1.30.6'

        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version=FROM_VERSION,
            to_version=TO_VERSION,
            state=kubernetes.KUBE_UPGRADING_NETWORKING,
        )

        mock_sanitize_kubeadm_configmap = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.sanitize_kubeadm_configmap',
                       mock_sanitize_kubeadm_configmap)
        p.start().return_value = 1
        self.addCleanup(p.stop)

        mock_backup_kube_control_plane = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.backup_kube_control_plane',
                       mock_backup_kube_control_plane)
        p.start()
        self.addCleanup(p.stop)

        mock_remove_kube_control_plane_backup = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.'
                       'remove_kube_control_plane_backup',
                       mock_remove_kube_control_plane_backup)
        p.start()
        self.addCleanup(p.stop)

        mock_get_kubernetes_system_images = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager._get_kubernetes_system_images',
                       mock_get_kubernetes_system_images)
        p.start()
        self.addCleanup(p.stop)

        mock_download_images_from_upstream_to_local_reg_and_crictl = mock.MagicMock()
        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager.'
            'download_images_from_upstream_to_local_reg_and_crictl',
            mock_download_images_from_upstream_to_local_reg_and_crictl)
        p.start()
        self.addCleanup(p.stop)

        mock_utils_execute = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.execute', mock_utils_execute)
        p.start()
        self.addCleanup(p.stop)

        mock_os_path_exists = mock.MagicMock()
        p = mock.patch('os.path.exists', mock_os_path_exists)
        p.start()
        self.addCleanup(p.stop)

        mock_open = mock.mock_open()
        p = mock.patch('builtins.open', mock_open)
        p.start()
        self.addCleanup(p.stop)

        mock_ruamel_yaml_safe_load = mock.MagicMock()
        p = mock.patch('ruamel.yaml.safe_load', mock_ruamel_yaml_safe_load)
        p.start()
        self.addCleanup(p.stop)

        mock_shutil_copy2 = mock.MagicMock()
        p = mock.patch('shutil.copy2', mock_shutil_copy2)
        p.start()
        self.addCleanup(p.stop)

        mock_render_jinja_template_from_file = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.render_jinja_template_from_file',
                       mock_render_jinja_template_from_file)
        p.start()
        self.addCleanup(p.stop)

        mock_kubectl_apply = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.kubectl_apply', mock_kubectl_apply)
        p.start()
        self.addCleanup(p.stop)

        mock_os_remove = mock.MagicMock()
        p = mock.patch('os.remove', mock_os_remove)
        p.start()
        self.addCleanup(p.stop)

        self.service.kube_upgrade_networking(self.context, TO_VERSION)

        mock_sanitize_kubeadm_configmap.assert_called_once()
        mock_backup_kube_control_plane.assert_not_called()
        mock_remove_kube_control_plane_backup.assert_called_once()
        mock_get_kubernetes_system_images.assert_not_called()
        mock_download_images_from_upstream_to_local_reg_and_crictl.assert_not_called()
        mock_utils_execute.assert_not_called()
        mock_open.assert_not_called()
        mock_ruamel_yaml_safe_load.assert_not_called()
        mock_shutil_copy2.assert_not_called()
        mock_render_jinja_template_from_file.assert_not_called()
        mock_kubectl_apply.assert_not_called()
        mock_os_path_exists.assert_not_called()
        mock_os_remove.assert_not_called()

        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state, kubernetes.KUBE_UPGRADING_NETWORKING_FAILED)

    def test_kube_upgrade_networking_failure_backup_control_plane_failed(self):
        """Test failed execution of kubernetes networking upgrade (backup control plane failed)
        """
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        FROM_VERSION = 'v1.29.2'
        TO_VERSION = 'v1.30.6'

        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version=FROM_VERSION,
            to_version=TO_VERSION,
            state=kubernetes.KUBE_UPGRADING_NETWORKING,
        )

        mock_sanitize_kubeadm_configmap = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.sanitize_kubeadm_configmap',
                       mock_sanitize_kubeadm_configmap)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_backup_kube_control_plane = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.backup_kube_control_plane',
                       mock_backup_kube_control_plane)
        p.start().side_effect = Exception("Fake error")
        self.addCleanup(p.stop)

        mock_remove_kube_control_plane_backup = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.'
                       'remove_kube_control_plane_backup',
                       mock_remove_kube_control_plane_backup)
        p.start()
        self.addCleanup(p.stop)

        mock_get_kubernetes_system_images = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager._get_kubernetes_system_images',
                       mock_get_kubernetes_system_images)
        p.start()
        self.addCleanup(p.stop)

        mock_download_images_from_upstream_to_local_reg_and_crictl = mock.MagicMock()
        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager.'
            'download_images_from_upstream_to_local_reg_and_crictl',
            mock_download_images_from_upstream_to_local_reg_and_crictl)
        p.start()
        self.addCleanup(p.stop)

        mock_utils_execute = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.execute', mock_utils_execute)
        p.start()
        self.addCleanup(p.stop)

        mock_os_path_exists = mock.MagicMock()
        p = mock.patch('os.path.exists', mock_os_path_exists)
        p.start()
        self.addCleanup(p.stop)

        mock_open = mock.mock_open()
        p = mock.patch('builtins.open', mock_open)
        p.start()
        self.addCleanup(p.stop)

        mock_ruamel_yaml_safe_load = mock.MagicMock()
        p = mock.patch('ruamel.yaml.safe_load', mock_ruamel_yaml_safe_load)
        p.start()
        self.addCleanup(p.stop)

        mock_shutil_copy2 = mock.MagicMock()
        p = mock.patch('shutil.copy2', mock_shutil_copy2)
        p.start()
        self.addCleanup(p.stop)

        mock_render_jinja_template_from_file = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.render_jinja_template_from_file',
                       mock_render_jinja_template_from_file)
        p.start()
        self.addCleanup(p.stop)

        mock_kubectl_apply = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.kubectl_apply', mock_kubectl_apply)
        p.start()
        self.addCleanup(p.stop)

        mock_os_remove = mock.MagicMock()
        p = mock.patch('os.remove', mock_os_remove)
        p.start()
        self.addCleanup(p.stop)

        self.service.kube_upgrade_networking(self.context, TO_VERSION)

        mock_sanitize_kubeadm_configmap.assert_called_once()
        mock_backup_kube_control_plane.assert_called_once()
        mock_remove_kube_control_plane_backup.assert_called_once()
        mock_get_kubernetes_system_images.assert_not_called()
        mock_download_images_from_upstream_to_local_reg_and_crictl.assert_not_called()
        mock_utils_execute.assert_not_called()
        mock_open.assert_not_called()
        mock_ruamel_yaml_safe_load.assert_not_called()
        mock_shutil_copy2.assert_not_called()
        mock_render_jinja_template_from_file.assert_not_called()
        mock_kubectl_apply.assert_not_called()
        mock_os_path_exists.assert_not_called()
        mock_os_remove.assert_not_called()

        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state, kubernetes.KUBE_UPGRADING_NETWORKING_FAILED)

    def test_kube_upgrade_networking_failure_image_download_failure(self):
        """Test failed execution of kubernetes networking upgrade (image download failure)
        """
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        FROM_VERSION = 'v1.29.2'
        TO_VERSION = 'v1.30.6'
        image_download_result = False
        upgrade_overrides_path_exists = False

        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version=FROM_VERSION,
            to_version=TO_VERSION,
            state=kubernetes.KUBE_UPGRADING_NETWORKING,
        )

        mock_sanitize_kubeadm_configmap = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.sanitize_kubeadm_configmap',
                       mock_sanitize_kubeadm_configmap)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_backup_kube_control_plane = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.backup_kube_control_plane',
                       mock_backup_kube_control_plane)
        p.start()
        self.addCleanup(p.stop)

        mock_get_kubernetes_system_images = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager._get_kubernetes_system_images',
                       mock_get_kubernetes_system_images)
        p.start()
        self.addCleanup(p.stop)

        mock_download_images_from_upstream_to_local_reg_and_crictl = mock.MagicMock()
        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager.'
            'download_images_from_upstream_to_local_reg_and_crictl',
            mock_download_images_from_upstream_to_local_reg_and_crictl)
        p.start().return_value = image_download_result
        self.addCleanup(p.stop)

        mock_utils_execute = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.execute', mock_utils_execute)
        p.start()
        self.addCleanup(p.stop)

        mock_os_path_exists = mock.MagicMock()
        p = mock.patch('os.path.exists', mock_os_path_exists)
        p.start().return_value = upgrade_overrides_path_exists
        self.addCleanup(p.stop)

        mock_open = mock.mock_open()
        p = mock.patch('builtins.open', mock_open)
        p.start()
        self.addCleanup(p.stop)

        mock_ruamel_yaml_safe_load = mock.MagicMock()
        p = mock.patch('ruamel.yaml.safe_load', mock_ruamel_yaml_safe_load)
        p.start()
        self.addCleanup(p.stop)

        mock_shutil_copy2 = mock.MagicMock()
        p = mock.patch('shutil.copy2', mock_shutil_copy2)
        p.start()
        self.addCleanup(p.stop)

        mock_render_jinja_template_from_file = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.render_jinja_template_from_file',
                       mock_render_jinja_template_from_file)
        p.start()
        self.addCleanup(p.stop)

        mock_kubectl_apply = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.kubectl_apply', mock_kubectl_apply)
        p.start()
        self.addCleanup(p.stop)

        mock_os_remove = mock.MagicMock()
        p = mock.patch('os.remove', mock_os_remove)
        p.start()
        self.addCleanup(p.stop)

        self.service.kube_upgrade_networking(self.context, TO_VERSION)

        mock_sanitize_kubeadm_configmap.assert_called_once()
        mock_backup_kube_control_plane.assert_called_once()
        mock_get_kubernetes_system_images.assert_called_once_with(TO_VERSION)
        mock_download_images_from_upstream_to_local_reg_and_crictl.assert_called_once()
        mock_utils_execute.assert_not_called()
        mock_open.assert_not_called()
        mock_ruamel_yaml_safe_load.assert_not_called()
        mock_shutil_copy2.assert_not_called()
        mock_render_jinja_template_from_file.assert_not_called()
        mock_kubectl_apply.assert_not_called()
        mock_os_path_exists.assert_called_once()
        mock_os_remove.assert_not_called()

        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state, kubernetes.KUBE_UPGRADING_NETWORKING_FAILED)

    def test_kube_upgrade_networking_failure_create_host_override_failure(self):
        """Test failed execution of kubernetes networking upgrade (create host overrides failed)
        """
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        FROM_VERSION = 'v1.29.2'
        TO_VERSION = 'v1.30.6'
        image_download_result = True
        upgrade_overrides_path_exists = False

        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version=FROM_VERSION,
            to_version=TO_VERSION,
            state=kubernetes.KUBE_UPGRADING_NETWORKING,
        )

        mock_sanitize_kubeadm_configmap = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.sanitize_kubeadm_configmap',
                       mock_sanitize_kubeadm_configmap)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_backup_kube_control_plane = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.backup_kube_control_plane',
                       mock_backup_kube_control_plane)
        p.start()
        self.addCleanup(p.stop)

        mock_get_kubernetes_system_images = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager._get_kubernetes_system_images',
                       mock_get_kubernetes_system_images)
        p.start()
        self.addCleanup(p.stop)

        mock_download_images_from_upstream_to_local_reg_and_crictl = mock.MagicMock()
        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager.'
            'download_images_from_upstream_to_local_reg_and_crictl',
            mock_download_images_from_upstream_to_local_reg_and_crictl)
        p.start().return_value = image_download_result
        self.addCleanup(p.stop)

        mock_utils_execute = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.execute', mock_utils_execute)
        p.start().side_effect = Exception("Fake error")
        self.addCleanup(p.stop)

        mock_os_path_exists = mock.MagicMock()
        p = mock.patch('os.path.exists', mock_os_path_exists)
        p.start().return_value = upgrade_overrides_path_exists
        self.addCleanup(p.stop)

        mock_open = mock.mock_open()
        p = mock.patch('builtins.open', mock_open)
        p.start()
        self.addCleanup(p.stop)

        mock_ruamel_yaml_safe_load = mock.MagicMock()
        p = mock.patch('ruamel.yaml.safe_load', mock_ruamel_yaml_safe_load)
        p.start()
        self.addCleanup(p.stop)

        mock_shutil_copy2 = mock.MagicMock()
        p = mock.patch('shutil.copy2', mock_shutil_copy2)
        p.start()
        self.addCleanup(p.stop)

        mock_render_jinja_template_from_file = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.render_jinja_template_from_file',
                       mock_render_jinja_template_from_file)
        p.start()
        self.addCleanup(p.stop)

        mock_kubectl_apply = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.kubectl_apply', mock_kubectl_apply)
        p.start()
        self.addCleanup(p.stop)

        mock_os_remove = mock.MagicMock()
        p = mock.patch('os.remove', mock_os_remove)
        p.start()
        self.addCleanup(p.stop)

        self.service.kube_upgrade_networking(self.context, TO_VERSION)

        mock_sanitize_kubeadm_configmap.assert_called_once()
        mock_backup_kube_control_plane.assert_called_once()
        mock_get_kubernetes_system_images.assert_called_once_with(TO_VERSION)
        mock_download_images_from_upstream_to_local_reg_and_crictl.assert_called_once()
        mock_utils_execute.assert_called_once()
        mock_open.assert_not_called()
        mock_ruamel_yaml_safe_load.assert_not_called()
        mock_shutil_copy2.assert_not_called()
        mock_render_jinja_template_from_file.assert_not_called()
        mock_kubectl_apply.assert_not_called()
        mock_os_path_exists.assert_called_once()
        mock_os_remove.assert_not_called()

        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state, kubernetes.KUBE_UPGRADING_NETWORKING_FAILED)

    def test_kube_upgrade_networking_failure_host_overrides_missing_cluster_pod_subnet(self):
        """Test failed execution of kubernetes networking upgrade
        (cluster_pod_subnet absent in host overrides)
        """
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        FROM_VERSION = 'v1.29.2'
        TO_VERSION = 'v1.30.6'
        image_download_result = True
        upgrade_overrides_path_exists = True
        upgrade_overrides = {"cluster_host_floating_address": "192.168.206.1",
                             "cluster_host_node_0_address": "192.168.206.2"}

        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version=FROM_VERSION,
            to_version=TO_VERSION,
            state=kubernetes.KUBE_UPGRADING_NETWORKING,
        )

        mock_sanitize_kubeadm_configmap = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.sanitize_kubeadm_configmap',
                       mock_sanitize_kubeadm_configmap)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_backup_kube_control_plane = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.backup_kube_control_plane',
                       mock_backup_kube_control_plane)
        p.start()
        self.addCleanup(p.stop)

        mock_get_kubernetes_system_images = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager._get_kubernetes_system_images',
                       mock_get_kubernetes_system_images)
        p.start()
        self.addCleanup(p.stop)

        mock_download_images_from_upstream_to_local_reg_and_crictl = mock.MagicMock()
        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager.'
            'download_images_from_upstream_to_local_reg_and_crictl',
            mock_download_images_from_upstream_to_local_reg_and_crictl)
        p.start().return_value = image_download_result
        self.addCleanup(p.stop)

        mock_utils_execute = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.execute', mock_utils_execute)
        p.start()
        self.addCleanup(p.stop)

        mock_os_path_exists = mock.MagicMock()
        p = mock.patch('os.path.exists', mock_os_path_exists)
        p.start().return_value = upgrade_overrides_path_exists
        self.addCleanup(p.stop)

        mock_open = mock.mock_open()
        p = mock.patch('builtins.open', mock_open)
        p.start()
        self.addCleanup(p.stop)

        mock_ruamel_yaml_safe_load = mock.MagicMock()
        p = mock.patch('ruamel.yaml.safe_load', mock_ruamel_yaml_safe_load)
        p.start().return_value = upgrade_overrides
        self.addCleanup(p.stop)

        mock_shutil_copy2 = mock.MagicMock()
        p = mock.patch('shutil.copy2', mock_shutil_copy2)
        p.start()
        self.addCleanup(p.stop)

        mock_render_jinja_template_from_file = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.render_jinja_template_from_file',
                       mock_render_jinja_template_from_file)
        p.start()
        self.addCleanup(p.stop)

        mock_kubectl_apply = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.kubectl_apply', mock_kubectl_apply)
        p.start()
        self.addCleanup(p.stop)

        mock_os_remove = mock.MagicMock()
        p = mock.patch('os.remove', mock_os_remove)
        p.start()
        self.addCleanup(p.stop)

        self.service.kube_upgrade_networking(self.context, TO_VERSION)

        mock_sanitize_kubeadm_configmap.assert_called_once()
        mock_backup_kube_control_plane.assert_called_once()
        mock_get_kubernetes_system_images.assert_called_once_with(TO_VERSION)
        mock_download_images_from_upstream_to_local_reg_and_crictl.assert_called_once()
        mock_utils_execute.assert_called_once()
        mock_os_path_exists.assert_called()
        mock_open.assert_called_once()
        mock_ruamel_yaml_safe_load.assert_called_once()
        mock_shutil_copy2.assert_not_called()
        mock_render_jinja_template_from_file.assert_not_called()
        mock_kubectl_apply.assert_not_called()
        mock_os_remove.assert_called_once()

        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state, kubernetes.KUBE_UPGRADING_NETWORKING_FAILED)

    def test_kube_upgrade_networking_failure_host_overrides_invalid_ip_address(self):
        """Test failed execution of kubernetes networking upgrade
        (cluster_host_floating_address invalid value)
        """
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        FROM_VERSION = 'v1.29.2'
        TO_VERSION = 'v1.30.6'
        image_download_result = True
        upgrade_overrides_path_exists = True
        upgrade_overrides = {"cluster_pod_subnet": "172.16.0.0/16",
                             "cluster_host_floating_address": "invalid_ip_address",
                             "cluster_host_node_0_address": "192.168.206.2"}

        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version=FROM_VERSION,
            to_version=TO_VERSION,
            state=kubernetes.KUBE_UPGRADING_NETWORKING,
        )

        mock_sanitize_kubeadm_configmap = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.sanitize_kubeadm_configmap',
                       mock_sanitize_kubeadm_configmap)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_backup_kube_control_plane = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.backup_kube_control_plane',
                       mock_backup_kube_control_plane)
        p.start()
        self.addCleanup(p.stop)

        mock_get_kubernetes_system_images = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager._get_kubernetes_system_images',
                       mock_get_kubernetes_system_images)
        p.start()
        self.addCleanup(p.stop)

        mock_download_images_from_upstream_to_local_reg_and_crictl = mock.MagicMock()
        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager.'
            'download_images_from_upstream_to_local_reg_and_crictl',
            mock_download_images_from_upstream_to_local_reg_and_crictl)
        p.start().return_value = image_download_result
        self.addCleanup(p.stop)

        mock_utils_execute = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.execute', mock_utils_execute)
        p.start()
        self.addCleanup(p.stop)

        mock_os_path_exists = mock.MagicMock()
        p = mock.patch('os.path.exists', mock_os_path_exists)
        p.start().return_value = upgrade_overrides_path_exists
        self.addCleanup(p.stop)

        mock_open = mock.mock_open()
        p = mock.patch('builtins.open', mock_open)
        p.start()
        self.addCleanup(p.stop)

        mock_ruamel_yaml_safe_load = mock.MagicMock()
        p = mock.patch('ruamel.yaml.safe_load', mock_ruamel_yaml_safe_load)
        p.start().return_value = upgrade_overrides
        self.addCleanup(p.stop)

        mock_shutil_copy2 = mock.MagicMock()
        p = mock.patch('shutil.copy2', mock_shutil_copy2)
        p.start()
        self.addCleanup(p.stop)

        mock_render_jinja_template_from_file = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.render_jinja_template_from_file',
                       mock_render_jinja_template_from_file)
        p.start()
        self.addCleanup(p.stop)

        mock_kubectl_apply = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.kubectl_apply', mock_kubectl_apply)
        p.start()
        self.addCleanup(p.stop)

        mock_os_remove = mock.MagicMock()
        p = mock.patch('os.remove', mock_os_remove)
        p.start()
        self.addCleanup(p.stop)

        self.service.kube_upgrade_networking(self.context, TO_VERSION)

        mock_sanitize_kubeadm_configmap.assert_called_once()
        mock_backup_kube_control_plane.assert_called_once()
        mock_get_kubernetes_system_images.assert_called_once_with(TO_VERSION)
        mock_download_images_from_upstream_to_local_reg_and_crictl.assert_called_once()
        mock_utils_execute.assert_called_once()
        mock_os_path_exists.assert_called()
        mock_open.assert_called_once()
        mock_ruamel_yaml_safe_load.assert_called_once()
        mock_shutil_copy2.assert_not_called()
        mock_render_jinja_template_from_file.assert_not_called()
        mock_kubectl_apply.assert_not_called()
        mock_os_remove.assert_called_once()

        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state, kubernetes.KUBE_UPGRADING_NETWORKING_FAILED)

    def test_kube_upgrade_networking_failure_template_render_error(self):
        """Test failed execution of kubernetes networking upgrade (Template rendering failure)
        """
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        FROM_VERSION = 'v1.29.2'
        TO_VERSION = 'v1.30.6'
        image_download_result = True
        upgrade_overrides_path_exists = True
        upgrade_overrides = {"cluster_pod_subnet": "172.16.0.0/16",
                             "cluster_host_floating_address": "192.168.206.1",
                             "cluster_host_node_0_address": "192.168.206.2"}

        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version=FROM_VERSION,
            to_version=TO_VERSION,
            state=kubernetes.KUBE_UPGRADING_NETWORKING,
        )

        mock_sanitize_kubeadm_configmap = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.sanitize_kubeadm_configmap',
                       mock_sanitize_kubeadm_configmap)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_backup_kube_control_plane = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.backup_kube_control_plane',
                       mock_backup_kube_control_plane)
        p.start()
        self.addCleanup(p.stop)

        mock_get_kubernetes_system_images = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager._get_kubernetes_system_images',
                       mock_get_kubernetes_system_images)
        p.start()
        self.addCleanup(p.stop)

        mock_download_images_from_upstream_to_local_reg_and_crictl = mock.MagicMock()
        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager.'
            'download_images_from_upstream_to_local_reg_and_crictl',
            mock_download_images_from_upstream_to_local_reg_and_crictl)
        p.start().return_value = image_download_result
        self.addCleanup(p.stop)

        mock_utils_execute = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.execute', mock_utils_execute)
        p.start()
        self.addCleanup(p.stop)

        mock_os_path_exists = mock.MagicMock()
        p = mock.patch('os.path.exists', mock_os_path_exists)
        p.start().return_value = upgrade_overrides_path_exists
        self.addCleanup(p.stop)

        mock_open = mock.mock_open()
        p = mock.patch('builtins.open', mock_open)
        p.start()
        self.addCleanup(p.stop)

        mock_ruamel_yaml_safe_load = mock.MagicMock()
        p = mock.patch('ruamel.yaml.safe_load', mock_ruamel_yaml_safe_load)
        p.start().return_value = upgrade_overrides
        self.addCleanup(p.stop)

        mock_render_jinja_template_from_file = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.render_jinja_template_from_file',
                       mock_render_jinja_template_from_file)
        p.start().side_effect = Exception("Fake error")
        self.addCleanup(p.stop)

        mock_kubectl_apply = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.kubectl_apply', mock_kubectl_apply)
        p.start()
        self.addCleanup(p.stop)

        mock_os_remove = mock.MagicMock()
        p = mock.patch('os.remove', mock_os_remove)
        p.start()
        self.addCleanup(p.stop)

        self.service.kube_upgrade_networking(self.context, TO_VERSION)

        mock_sanitize_kubeadm_configmap.assert_called_once()
        mock_backup_kube_control_plane.assert_called_once()
        mock_get_kubernetes_system_images.assert_called_once_with(TO_VERSION)
        mock_download_images_from_upstream_to_local_reg_and_crictl.assert_called_once()
        mock_utils_execute.assert_called_once()
        mock_os_path_exists.assert_called()
        mock_open.assert_called()
        mock_ruamel_yaml_safe_load.assert_called_once()
        # Assert kubectl apply called at max once for coredns where template is copied not rendered.
        assert mock_kubectl_apply.call_count <= 1
        mock_os_remove.assert_called_once()

        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state, kubernetes.KUBE_UPGRADING_NETWORKING_FAILED)

    def test_kube_upgrade_networking_failure_kubectl_apply_error(self):
        """Test failed execution of kubernetes networking upgrade (Manifest apply failure)
        """
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        FROM_VERSION = 'v1.29.2'
        TO_VERSION = 'v1.30.6'
        image_download_result = True
        upgrade_overrides_path_exists = True
        upgrade_overrides = {"cluster_pod_subnet": "172.16.0.0/16",
                             "cluster_host_floating_address": "192.168.206.1",
                             "cluster_host_node_0_address": "192.168.206.2"}

        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version=FROM_VERSION,
            to_version=TO_VERSION,
            state=kubernetes.KUBE_UPGRADING_NETWORKING,
        )

        mock_sanitize_kubeadm_configmap = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.sanitize_kubeadm_configmap',
                       mock_sanitize_kubeadm_configmap)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_backup_kube_control_plane = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.backup_kube_control_plane',
                       mock_backup_kube_control_plane)
        p.start()
        self.addCleanup(p.stop)

        mock_get_kubernetes_system_images = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager._get_kubernetes_system_images',
                       mock_get_kubernetes_system_images)
        p.start()
        self.addCleanup(p.stop)

        mock_download_images_from_upstream_to_local_reg_and_crictl = mock.MagicMock()
        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager.'
            'download_images_from_upstream_to_local_reg_and_crictl',
            mock_download_images_from_upstream_to_local_reg_and_crictl)
        p.start().return_value = image_download_result
        self.addCleanup(p.stop)

        mock_utils_execute = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.execute', mock_utils_execute)
        p.start()
        self.addCleanup(p.stop)

        mock_os_path_exists = mock.MagicMock()
        p = mock.patch('os.path.exists', mock_os_path_exists)
        p.start().return_value = upgrade_overrides_path_exists
        self.addCleanup(p.stop)

        mock_open = mock.mock_open()
        p = mock.patch('builtins.open', mock_open)
        p.start()
        self.addCleanup(p.stop)

        mock_ruamel_yaml_safe_load = mock.MagicMock()
        p = mock.patch('ruamel.yaml.safe_load', mock_ruamel_yaml_safe_load)
        p.start().return_value = upgrade_overrides
        self.addCleanup(p.stop)

        mock_kubectl_apply = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.kubectl_apply', mock_kubectl_apply)
        p.start().side_effect = Exception("Fake error")
        self.addCleanup(p.stop)

        mock_os_remove = mock.MagicMock()
        p = mock.patch('os.remove', mock_os_remove)
        p.start()
        self.addCleanup(p.stop)

        self.service.kube_upgrade_networking(self.context, TO_VERSION)

        mock_sanitize_kubeadm_configmap.assert_called_once()
        mock_backup_kube_control_plane.assert_called_once()
        mock_get_kubernetes_system_images.assert_called_once_with(TO_VERSION)
        mock_download_images_from_upstream_to_local_reg_and_crictl.assert_called_once()
        mock_utils_execute.assert_called_once()
        mock_os_path_exists.assert_called()
        mock_open.assert_called()
        mock_ruamel_yaml_safe_load.assert_called_once()
        mock_os_remove.assert_called_once()

        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state, kubernetes.KUBE_UPGRADING_NETWORKING_FAILED)

    def test_kube_upgrade_storage_success(self):
        """Test successful execution of kubernetes storage upgrade
        """
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        FROM_VERSION = 'v1.29.2'
        TO_VERSION = 'v1.30.6'
        storage_images = {'snapshot_controller_img': 'fake_snapshot_controller_img'}
        image_download_result = True
        manifest_apply_result = True

        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version=FROM_VERSION,
            to_version=TO_VERSION,
            state=kubernetes.KUBE_UPGRADING_STORAGE,
        )

        mock_get_kubernetes_system_images = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager._get_kubernetes_system_images',
                       mock_get_kubernetes_system_images)
        p.start().return_value = storage_images
        self.addCleanup(p.stop)

        mock_download_images_from_upstream_to_local_reg_and_crictl = mock.MagicMock()
        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager.'
            'download_images_from_upstream_to_local_reg_and_crictl',
            mock_download_images_from_upstream_to_local_reg_and_crictl)
        p.start().return_value = image_download_result
        self.addCleanup(p.stop)

        mock_generate_manifests_and_apply = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager._generate_k8s_manifests_and_apply',
                       mock_generate_manifests_and_apply)
        p.start().return_value = manifest_apply_result
        self.addCleanup(p.stop)

        self.service.kube_upgrade_storage(self.context, TO_VERSION)

        mock_get_kubernetes_system_images.assert_called_once_with(TO_VERSION)
        mock_download_images_from_upstream_to_local_reg_and_crictl.assert_called_once()

        expected_apply_calls = [
            mock.call(mock.ANY,
                      os.path.join(kubernetes.KUBERNETES_CONF_DIR,
                                   'update_rbac-volume-snapshot-controller.yaml'),
                      is_template=False,
                      values=mock.ANY),
            mock.call(mock.ANY,
                      os.path.join(kubernetes.KUBERNETES_CONF_DIR,
                                   'update_snapshot-controller.yaml'),
                      is_template=True,
                      values=mock.ANY)]
        mock_generate_manifests_and_apply.assert_has_calls(expected_apply_calls, any_order=True)
        self.assertEqual(mock_generate_manifests_and_apply.call_count, 2)

        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state, kubernetes.KUBE_UPGRADED_STORAGE)

    def test_kube_upgrade_storage_failure_image_download_failed(self):
        """Test failed execution of kubernetes storage upgrade (Image download failed)
        """
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        FROM_VERSION = 'v1.29.2'
        TO_VERSION = 'v1.30.6'
        storage_images = {'snapshot_controller_img': 'fake_snapshot_controller_img'}
        image_download_result = False

        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version=FROM_VERSION,
            to_version=TO_VERSION,
            state=kubernetes.KUBE_UPGRADING_STORAGE,
        )

        mock_get_kubernetes_system_images = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager._get_kubernetes_system_images',
                       mock_get_kubernetes_system_images)
        p.start().return_value = storage_images
        self.addCleanup(p.stop)

        mock_download_images_from_upstream_to_local_reg_and_crictl = mock.MagicMock()
        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager.'
            'download_images_from_upstream_to_local_reg_and_crictl',
            mock_download_images_from_upstream_to_local_reg_and_crictl)
        p.start().return_value = image_download_result
        self.addCleanup(p.stop)

        mock_generate_manifests_and_apply = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.'
                       '_generate_k8s_manifests_and_apply',
                       mock_generate_manifests_and_apply)
        p.start()
        self.addCleanup(p.stop)

        self.service.kube_upgrade_storage(self.context, TO_VERSION)

        mock_get_kubernetes_system_images.assert_called_once_with(TO_VERSION)
        mock_download_images_from_upstream_to_local_reg_and_crictl.assert_called_once()
        mock_generate_manifests_and_apply.assert_not_called()

        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state, kubernetes.KUBE_UPGRADING_STORAGE_FAILED)

    def test_kube_upgrade_storage_failure_manifests_apply_failure(self):
        """Test failed execution of kubernetes storage upgrade (Manifests apply failure)
        """
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        FROM_VERSION = 'v1.29.2'
        TO_VERSION = 'v1.30.6'
        storage_images = {'snapshot_controller_img': 'fake_snapshot_controller_img'}
        image_download_result = True

        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version=FROM_VERSION,
            to_version=TO_VERSION,
            state=kubernetes.KUBE_UPGRADING_STORAGE,
        )

        mock_get_kubernetes_system_images = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager._get_kubernetes_system_images',
                       mock_get_kubernetes_system_images)
        p.start().return_value = storage_images
        self.addCleanup(p.stop)

        mock_download_images_from_upstream_to_local_reg_and_crictl = mock.MagicMock()
        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager.'
            'download_images_from_upstream_to_local_reg_and_crictl',
            mock_download_images_from_upstream_to_local_reg_and_crictl)
        p.start().return_value = image_download_result
        self.addCleanup(p.stop)

        mock_generate_manifests_and_apply = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.'
                       '_generate_k8s_manifests_and_apply',
                       mock_generate_manifests_and_apply)
        p.start().side_effect = [True, False]
        self.addCleanup(p.stop)

        self.service.kube_upgrade_storage(self.context, TO_VERSION)

        mock_get_kubernetes_system_images.assert_called_once_with(TO_VERSION)
        mock_download_images_from_upstream_to_local_reg_and_crictl.assert_called_once()
        expected_apply_calls = [
            mock.call(mock.ANY,
                      os.path.join(kubernetes.KUBERNETES_CONF_DIR,
                                   'update_rbac-volume-snapshot-controller.yaml'),
                      is_template=False,
                      values=mock.ANY),
            mock.call(mock.ANY,
                      os.path.join(kubernetes.KUBERNETES_CONF_DIR,
                                   'update_snapshot-controller.yaml'),
                      is_template=True,
                      values=mock.ANY)]
        mock_generate_manifests_and_apply.assert_has_calls(expected_apply_calls, any_order=True)
        self.assertEqual(mock_generate_manifests_and_apply.call_count, 2)

        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state, kubernetes.KUBE_UPGRADING_STORAGE_FAILED)

    # def test_kube_host_uncordon(self):
    #     system_dict = self.system.as_dict()
    #     system_dict['system_mode'] = constants.SYSTEM_MODE_SIMPLEX
    #     self.dbapi.isystem_update(self.system.uuid, system_dict)

    #     # Create controller-0
    #     config_uuid = str(uuid.uuid4())
    #     self._create_test_ihost(
    #         personality=constants.CONTROLLER,
    #         hostname='controller-0',
    #         uuid=str(uuid.uuid4()),
    #         config_status=None,
    #         config_applied=config_uuid,
    #         config_target=config_uuid,
    #         invprovision=constants.PROVISIONED,
    #         administrative=constants.ADMIN_UNLOCKED,
    #         operational=constants.OPERATIONAL_ENABLED,
    #         availability=constants.AVAILABILITY_ONLINE,
    #     )
    #     # Create an upgrade
    #     utils.create_test_kube_upgrade(
    #         from_version='v1.42.1',
    #         to_version='v1.42.2',
    #         state=kubernetes.KUBE_UPGRADE_UNCORDON,
    #     )

    #     self.fake_subprocess_popen.returncode = 0

    #     # Uncordon node
    #     self.service.kube_host_uncordon(self.context, constants.CONTROLLER_0_HOSTNAME)

    #     # Verify that we called kubectl command to uncordon
    #     uncordon_cmd = ['kubectl', '--kubeconfig=%s' % kubernetes.KUBERNETES_ADMIN_CONF,
    #                     'uncordon', constants.CONTROLLER_0_HOSTNAME]
    #     self.mock_subprocess_popen.assert_called_with(uncordon_cmd, stdout=-1, stderr=-1,
    #                                                   universal_newlines=True)

    #     # Verify that the upgrade state was updated
    #     updated_upgrade = self.dbapi.kube_upgrade_get_one()
    #     self.assertEqual(updated_upgrade.state,
    #                      kubernetes.KUBE_UPGRADE_UNCORDON_COMPLETE)

#    @mock.patch('sysinv.conductor.manager.'
#                'ConductorManager._config_apply_runtime_manifest')
#    @mock.patch('sysinv.conductor.manager.'
#                'ConductorManager._config_update_hosts')
#    def test_kube_upgrade_control_plane_first_master_patch_version(self,
#            mock_config_update_hosts, mock_config_apply_runtime_manifest):
#        mock_config_update_hosts.return_value = "6c5aa183-4884-46e6-b86a-b29e6b08dedb"
#        # Create an upgrade
#        utils.create_test_kube_upgrade(
#            from_version='v1.42.1',
#            to_version='v1.42.2',
#            state=kubernetes.KUBE_UPGRADING_FIRST_MASTER,
#        )
#        # Create controller-0
#        config_uuid = str(uuid.uuid4())
#        c0 = self._create_test_ihost(
#            personality=constants.CONTROLLER,
#            hostname='controller-0',
#            uuid=str(uuid.uuid4()),
#            config_status=None,
#            config_applied=config_uuid,
#            config_target=config_uuid,
#            invprovision=constants.PROVISIONED,
#            administrative=constants.ADMIN_UNLOCKED,
#            operational=constants.OPERATIONAL_ENABLED,
#            availability=constants.AVAILABILITY_ONLINE,
#        )
#        # Set the target version for controller-0
#        self.dbapi.kube_host_upgrade_update(1, {'target_version': 'v1.42.2'})
#        # Make the control plane upgrade pass
#        self.kube_get_control_plane_versions_result = {
#            'controller-0': 'v1.42.1',
#            'controller-1': 'v1.42.1',
#            'worker-0': 'v1.42.1'}
#
#        mock_sanitize_kubeadm_configmap = mock.MagicMock()
#        p2 = mock.patch(
#            'sysinv.conductor.manager.ConductorManager.sanitize_kubeadm_configmap',
#            mock_sanitize_kubeadm_configmap)
#        p2.start().return_value = 0
#        self.addCleanup(p2.stop)
#
#        self.service._kube = FakeKubeOperator()
#
#        # Speed up the test
#        kubernetes.MANIFEST_APPLY_INTERVAL = 1
#        kubernetes.POD_START_INTERVAL = 1
#
#        # Upgrade the control plane
#        self.service.kube_upgrade_control_plane(self.context, c0.uuid)
#
#        personalities = [constants.CONTROLLER]
#        config_dict = {
#            "personalities": personalities,
#            "host_uuids": [c0.uuid],
#            "classes": ['platform::kubernetes::upgrade_first_control_plane'],
#            puppet_common.REPORT_STATUS_CFG:
#                puppet_common.REPORT_UPGRADE_CONTROL_PLANE
#        }
#
#        mock_config_apply_runtime_manifest.assert_called_with(mock.ANY,
#            '6c5aa183-4884-46e6-b86a-b29e6b08dedb', config_dict)

#    @mock.patch('sysinv.conductor.manager.'
#                'ConductorManager._config_apply_runtime_manifest')
#    @mock.patch('sysinv.conductor.manager.'
#                'ConductorManager._config_update_hosts')
#    def test_kube_upgrade_control_plane_first_master_minor_version(self,
#            mock_config_update_hosts, mock_config_apply_runtime_manifest):
#        mock_config_update_hosts.return_value = "6c5aa183-4884-46e6-b86a-b29e6b08dedb"
#        # Create an upgrade
#        utils.create_test_kube_upgrade(
#            from_version='v1.41.5',
#            to_version='v1.42.2',
#            state=kubernetes.KUBE_UPGRADING_FIRST_MASTER,
#        )
#        # Create controller-0
#        config_uuid = str(uuid.uuid4())
#        c0 = self._create_test_ihost(
#            personality=constants.CONTROLLER,
#            hostname='controller-0',
#            uuid=str(uuid.uuid4()),
#            config_status=None,
#            config_applied=config_uuid,
#            config_target=config_uuid,
#            invprovision=constants.PROVISIONED,
#            administrative=constants.ADMIN_UNLOCKED,
#            operational=constants.OPERATIONAL_ENABLED,
#            availability=constants.AVAILABILITY_ONLINE,
#        )
#        # Set the target version for controller-0
#        self.dbapi.kube_host_upgrade_update(1, {'target_version': 'v1.42.2'})
#        # Make the control plane upgrade pass
#        self.kube_get_control_plane_versions_result = {
#            'controller-0': 'v1.41.5',
#            'controller-1': 'v1.41.5',
#            'worker-0': 'v1.41.5'}
#        self.kube_get_kubelet_versions_result = {
#            'controller-0': 'v1.41.5',
#            'controller-1': 'v1.41.5',
#            'worker-0': 'v1.41.5'}
#
#        mock_sanitize_kubeadm_configmap = mock.MagicMock()
#        p2 = mock.patch(
#            'sysinv.conductor.manager.ConductorManager.sanitize_kubeadm_configmap',
#            mock_sanitize_kubeadm_configmap)
#        p2.start().return_value = 0
#        self.addCleanup(p2.stop)
#
#        self.service._kube = FakeKubeOperator()
#
#        # Speed up the test
#        kubernetes.MANIFEST_APPLY_INTERVAL = 1
#        kubernetes.POD_START_INTERVAL = 1
#
#        # Upgrade the control plane
#        self.service.kube_upgrade_control_plane(self.context, c0.uuid)
#
#        personalities = [constants.CONTROLLER]
#        config_dict = {
#            "personalities": personalities,
#            "host_uuids": [c0.uuid],
#            "classes": ['platform::kubernetes::upgrade_first_control_plane'],
#            puppet_common.REPORT_STATUS_CFG:
#                puppet_common.REPORT_UPGRADE_CONTROL_PLANE
#        }
#
#        mock_config_apply_runtime_manifest.assert_called_with(mock.ANY,
#            '6c5aa183-4884-46e6-b86a-b29e6b08dedb', config_dict)

#    @mock.patch('sysinv.conductor.manager.'
#                'ConductorManager._config_apply_runtime_manifest')
#    @mock.patch('sysinv.conductor.manager.'
#                'ConductorManager._config_update_hosts')
#    def test_kube_upgrade_control_plane_first_master_fail_skew_fail(self,
#            mock_config_update_hosts, mock_config_apply_runtime_manifest):
#        mock_config_update_hosts.return_value = "6c5aa183-4884-46e6-b86a-b29e6b08dedb"
#        # Create an upgrade
#        utils.create_test_kube_upgrade(
#            from_version='v1.41.5',
#            to_version='v1.42.2',
#            state=kubernetes.KUBE_UPGRADING_FIRST_MASTER,
#        )
#        # Create controller-0
#        config_uuid = str(uuid.uuid4())
#        c0 = self._create_test_ihost(
#            personality=constants.CONTROLLER,
#            hostname='controller-0',
#            uuid=str(uuid.uuid4()),
#            config_status=None,
#            config_applied=config_uuid,
#            config_target=config_uuid,
#            invprovision=constants.PROVISIONED,
#            administrative=constants.ADMIN_UNLOCKED,
#            operational=constants.OPERATIONAL_ENABLED,
#            availability=constants.AVAILABILITY_ONLINE,
#        )
#        # Set the target version for controller-0
#        self.dbapi.kube_host_upgrade_update(1, {'target_version': 'v1.42.2'})
#        # Make the control plane upgrade fail, one node has large kubelet skew,
#        # e.g., 42 - 38 = 4 (>3 tolerance)
#        self.kube_get_control_plane_versions_result = {
#            'controller-0': 'v1.41.5',
#            'controller-1': 'v1.41.5',
#            'worker-0': 'v1.41.5'}
#        self.kube_get_kubelet_versions_result = {
#            'controller-0': 'v1.41.5',
#            'controller-1': 'v1.41.5',
#            'worker-0': 'v1.38.5'}
#
#        mock_sanitize_kubeadm_configmap = mock.MagicMock()
#        p2 = mock.patch(
#            'sysinv.conductor.manager.ConductorManager.sanitize_kubeadm_configmap',
#            mock_sanitize_kubeadm_configmap)
#        p2.start().return_value = 0
#        self.addCleanup(p2.stop)
#
#        self.service._kube = FakeKubeOperator()
#
#        # Speed up the test
#        kubernetes.MANIFEST_APPLY_INTERVAL = 1
#        kubernetes.POD_START_INTERVAL = 1
#
#        # Upgrade the control plane; fails policy skew semantic check
#        self.service.kube_upgrade_control_plane(self.context, c0.uuid)
#        mock_config_apply_runtime_manifest.assert_not_called()

#    @mock.patch('sysinv.conductor.manager.'
#                'ConductorManager._config_apply_runtime_manifest')
#    @mock.patch('sysinv.conductor.manager.'
#                'ConductorManager._config_update_hosts')
#    def test_kube_upgrade_control_plane_first_master_fail_skew_exact(self,
#            mock_config_update_hosts, mock_config_apply_runtime_manifest):
#        mock_config_update_hosts.return_value = "6c5aa183-4884-46e6-b86a-b29e6b08dedb"
#        # Create an upgrade
#        utils.create_test_kube_upgrade(
#            from_version='v1.41.5',
#            to_version='v1.42.2',
#            state=kubernetes.KUBE_UPGRADING_FIRST_MASTER,
#        )
#        # Create controller-0
#        config_uuid = str(uuid.uuid4())
#        c0 = self._create_test_ihost(
#            personality=constants.CONTROLLER,
#            hostname='controller-0',
#            uuid=str(uuid.uuid4()),
#            config_status=None,
#            config_applied=config_uuid,
#            config_target=config_uuid,
#            invprovision=constants.PROVISIONED,
#            administrative=constants.ADMIN_UNLOCKED,
#            operational=constants.OPERATIONAL_ENABLED,
#            availability=constants.AVAILABILITY_ONLINE,
#        )
#        # Set the target version for controller-0
#        self.dbapi.kube_host_upgrade_update(1, {'target_version': 'v1.42.2'})
#        # Make the control plane upgrade pass, with 3 kubelet skew
#        # e.g., 42 - 39 = 3 (exact tolerance)
#        self.kube_get_control_plane_versions_result = {
#            'controller-0': 'v1.41.5',
#            'controller-1': 'v1.41.5',
#            'worker-0': 'v1.41.5'}
#        self.kube_get_kubelet_versions_result = {
#            'controller-0': 'v1.41.5',
#            'controller-1': 'v1.41.5',
#            'worker-0': 'v1.39.5'}
#
#        mock_sanitize_kubeadm_configmap = mock.MagicMock()
#        p2 = mock.patch(
#            'sysinv.conductor.manager.ConductorManager.sanitize_kubeadm_configmap',
#            mock_sanitize_kubeadm_configmap)
#        p2.start().return_value = 0
#        self.addCleanup(p2.stop)
#
#        self.service._kube = FakeKubeOperator()
#
#        # Speed up the test
#        kubernetes.MANIFEST_APPLY_INTERVAL = 1
#        kubernetes.POD_START_INTERVAL = 1
#
#        # Upgrade the control plane
#        self.service.kube_upgrade_control_plane(self.context, c0.uuid)
#
#        personalities = [constants.CONTROLLER]
#        config_dict = {
#            "personalities": personalities,
#            "host_uuids": [c0.uuid],
#            "classes": ['platform::kubernetes::upgrade_first_control_plane'],
#            puppet_common.REPORT_STATUS_CFG:
#                puppet_common.REPORT_UPGRADE_CONTROL_PLANE
#        }
#
#        mock_config_apply_runtime_manifest.assert_called_with(mock.ANY,
#            '6c5aa183-4884-46e6-b86a-b29e6b08dedb', config_dict)

#    @mock.patch('sysinv.conductor.manager.'
#                'ConductorManager._config_apply_runtime_manifest')
#    @mock.patch('sysinv.conductor.manager.'
#                'ConductorManager._config_update_hosts')
#    def test_kube_upgrade_control_plane_second_master(self, mock_config_update_hosts,
#                                                  mock_config_apply_runtime_manifest):
#        mock_config_update_hosts.return_value = "6c5aa183-4884-46e6-b86a-b29e6b08dedb"
#        # Create an upgrade
#        utils.create_test_kube_upgrade(
#            from_version='v1.42.1',
#            to_version='v1.42.2',
#            state=kubernetes.KUBE_UPGRADING_SECOND_MASTER,
#        )
#        # Create controller-0
#        config_uuid = str(uuid.uuid4())
#        self._create_test_ihost(
#            personality=constants.CONTROLLER,
#            hostname='controller-0',
#            uuid=str(uuid.uuid4()),
#            config_status=None,
#            config_applied=config_uuid,
#            config_target=config_uuid,
#            invprovision=constants.PROVISIONED,
#            administrative=constants.ADMIN_UNLOCKED,
#            operational=constants.OPERATIONAL_ENABLED,
#            availability=constants.AVAILABILITY_ONLINE,
#            mgmt_mac='00:11:22:33:44:55',
#        )
#        # Set the target version for controller-0
#        self.dbapi.kube_host_upgrade_update(1, {'target_version': 'v1.42.2'})
#        # Create controller-1
#        config_uuid = str(uuid.uuid4())
#        c1 = self._create_test_ihost(
#            personality=constants.CONTROLLER,
#            hostname='controller-1',
#            uuid=str(uuid.uuid4()),
#            config_status=None,
#            config_applied=config_uuid,
#            config_target=config_uuid,
#            invprovision=constants.PROVISIONED,
#            administrative=constants.ADMIN_UNLOCKED,
#            operational=constants.OPERATIONAL_ENABLED,
#            availability=constants.AVAILABILITY_ONLINE,
#            mgmt_mac='00:11:22:33:44:56',
#            mgmt_ip='1.2.3.5',
#        )
#        # Set the target version for controller-1
#        self.dbapi.kube_host_upgrade_update(2, {'target_version': 'v1.42.2'})
#        # Make the control plane upgrade pass
#        self.kube_get_control_plane_versions_result = {
#            'controller-0': 'v1.42.2',
#            'controller-1': 'v1.42.1',
#            'worker-0': 'v1.42.1'}
#
#        # Speed up the test
#        kubernetes.MANIFEST_APPLY_INTERVAL = 1
#        kubernetes.POD_START_INTERVAL = 1
#
#        # Upgrade the control plane
#        self.service.kube_upgrade_control_plane(self.context, c1.uuid)
#
#        personalities = [constants.CONTROLLER]
#        config_dict = {
#            "personalities": personalities,
#            "host_uuids": [c1.uuid],
#            "classes": ['platform::kubernetes::upgrade_control_plane'],
#            puppet_common.REPORT_STATUS_CFG:
#                puppet_common.REPORT_UPGRADE_CONTROL_PLANE
#        }
#
#        mock_config_apply_runtime_manifest.assert_called_with(mock.ANY,
#            '6c5aa183-4884-46e6-b86a-b29e6b08dedb', config_dict)

#    @mock.patch('os.path.isdir', return_value=True)
#    @mock.patch('shutil.copytree')
#    @mock.patch('sysinv.conductor.manager.tempfile.mkdtemp', return_value='/tmp/mock-temp-dir')
#    def test_kube_upgrade_kubelet_controller(self, mock_mkdtemp, mock_copytree, mock_isdir):
#        # Create an upgrade
#        utils.create_test_kube_upgrade(
#            from_version='v1.42.1',
#            to_version='v1.42.2',
#            state=kubernetes.KUBE_UPGRADED_SECOND_MASTER,
#        )
#        # Create controller-0
#        config_uuid = str(uuid.uuid4())
#        c0 = self._create_test_ihost(
#            personality=constants.CONTROLLER,
#            hostname='controller-0',
#            uuid=str(uuid.uuid4()),
#            config_status=None,
#            config_applied=config_uuid,
#            config_target=config_uuid,
#            invprovision=constants.PROVISIONED,
#            administrative=constants.ADMIN_UNLOCKED,
#            operational=constants.OPERATIONAL_ENABLED,
#            availability=constants.AVAILABILITY_ONLINE,
#        )
#        # Set the target version for controller-0
#        self.dbapi.kube_host_upgrade_update(1, {'target_version': 'v1.42.2'})
#        # Make the kubelet upgrade pass
#        self.kube_get_kubelet_versions_result = {
#            'controller-0': 'v1.42.2',
#            'controller-1': 'v1.42.1',
#            'worker-0': 'v1.42.1'}
#
#        # Speed up the test
#        kubernetes.MANIFEST_APPLY_INTERVAL = 1
#        kubernetes.POD_START_INTERVAL = 1
#
#        # Upgrade the kubelet
#        self.service.kube_upgrade_kubelet(self.context, c0.uuid)
#
#        # Verify that the upgrade state was not updated
#        updated_upgrade = self.dbapi.kube_upgrade_get_one()
#        self.assertEqual(updated_upgrade.state,
#                         kubernetes.KUBE_UPGRADED_SECOND_MASTER)
#
#        # Verify that the host upgrade status is upgraded-kubelet
#        updated_host_upgrade = self.dbapi.kube_host_upgrade_get(1)
#        self.assertEqual(updated_host_upgrade.status,
#                         kubernetes.KUBE_HOST_UPGRADED_KUBELET)

#    def test_kube_upgrade_kubelet_second_master(self):
#        # Create an upgrade
#        utils.create_test_kube_upgrade(
#            from_version='v1.42.1',
#            to_version='v1.42.2',
#            state=kubernetes.KUBE_UPGRADING_SECOND_MASTER,
#        )
#        # Create controller-0
#        config_uuid = str(uuid.uuid4())
#        self._create_test_ihost(
#            personality=constants.CONTROLLER,
#            hostname='controller-0',
#            uuid=str(uuid.uuid4()),
#            config_status=None,
#            config_applied=config_uuid,
#            config_target=config_uuid,
#            invprovision=constants.PROVISIONED,
#            administrative=constants.ADMIN_UNLOCKED,
#            operational=constants.OPERATIONAL_ENABLED,
#            availability=constants.AVAILABILITY_ONLINE,
#            mgmt_mac='00:11:22:33:44:55',
#        )
#        # Set the target version for controller-0
#        self.dbapi.kube_host_upgrade_update(1, {'target_version': 'v1.42.2'})
#        # Create controller-1
#        config_uuid = str(uuid.uuid4())
#        c1 = self._create_test_ihost(
#            personality=constants.CONTROLLER,
#            hostname='controller-1',
#            uuid=str(uuid.uuid4()),
#            config_status=None,
#            config_applied=config_uuid,
#            config_target=config_uuid,
#            invprovision=constants.PROVISIONED,
#            administrative=constants.ADMIN_UNLOCKED,
#            operational=constants.OPERATIONAL_ENABLED,
#            availability=constants.AVAILABILITY_ONLINE,
#            mgmt_mac='00:11:22:33:44:56',
#        )
#        # Set the target version for controller-1
#        self.dbapi.kube_host_upgrade_update(2, {'target_version': 'v1.42.2'})
#        # Make the kubelet upgrade pass
#        self.kube_get_kubelet_versions_result = {
#            'controller-0': 'v1.42.2',
#            'controller-1': 'v1.42.2'}
#        # Make the upgrade pass
#        self.kube_get_control_plane_versions_result = {
#            'controller-0': 'v1.42.2',
#            'controller-1': 'v1.42.2'}
#
#        # Speed up the test
#        kubernetes.MANIFEST_APPLY_INTERVAL = 1
#        kubernetes.POD_START_INTERVAL = 1
#
#        # Upgrade the kubelet
#        self.service.kube_upgrade_kubelet(self.context, c1.uuid)
#
#        # Verify that the host upgrade status was cleared
#        updated_host_upgrade = self.dbapi.kube_host_upgrade_get(1)
#        self.assertEqual(updated_host_upgrade.status, None)

#    def test_kube_upgrade_kubelet_controller_upgrade_fail(self):
#        # Create an upgrade
#        utils.create_test_kube_upgrade(
#            from_version='v1.42.1',
#            to_version='v1.42.2',
#            state=kubernetes.KUBE_UPGRADING_KUBELETS,
#        )
#        # Create controller-0
#        config_uuid = str(uuid.uuid4())
#        c0 = self._create_test_ihost(
#            personality=constants.CONTROLLER,
#            hostname='controller-0',
#            uuid=str(uuid.uuid4()),
#            config_status=None,
#            config_applied=config_uuid,
#            config_target=config_uuid,
#            invprovision=constants.PROVISIONED,
#            administrative=constants.ADMIN_UNLOCKED,
#            operational=constants.OPERATIONAL_ENABLED,
#            availability=constants.AVAILABILITY_ONLINE,
#        )
#        # Set the target version for controller-0
#        self.dbapi.kube_host_upgrade_update(1, {'target_version': 'v1.42.2'})
#
#        # Speed up the test
#        kubernetes.MANIFEST_APPLY_INTERVAL = 1
#        kubernetes.POD_START_INTERVAL = 1
#        kubernetes.POD_START_TIMEOUT = 1
#
#        # Upgrade the kubelet
#        self.service.kube_upgrade_kubelet(self.context, c0.uuid)
#
#        # Verify that the upgrade state was not updated
#        updated_upgrade = self.dbapi.kube_upgrade_get_one()
#        self.assertEqual(updated_upgrade.state,
#                         kubernetes.KUBE_UPGRADING_KUBELETS)
#
#        # Verify that the host upgrade status was cleared
#        updated_host_upgrade = self.dbapi.kube_host_upgrade_get(1)
#        self.assertIsNotNone(updated_host_upgrade.status)

    def test_backup_kube_control_plane(self):
        """ The unit test covers the success path of the method
            backup_kube_control_plane
        """
        mock_remove_kube_control_plane_backup = mock.MagicMock()
        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager.'
            'remove_kube_control_plane_backup',
            mock_remove_kube_control_plane_backup)
        p.start()
        self.addCleanup(p.stop)

        mock_backup_kube_static_pods = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.backup_kube_static_pods',
            mock_backup_kube_static_pods)
        p.start()
        self.addCleanup(p.stop)

        mock_etcd_snapshot_etcd = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.etcd.snapshot_etcd',
            mock_etcd_snapshot_etcd)
        p.start()
        self.addCleanup(p.stop)

        self.service.backup_kube_control_plane(self.context)
        mock_remove_kube_control_plane_backup.assert_called()
        mock_backup_kube_static_pods.assert_called()
        mock_etcd_snapshot_etcd.assert_called()

    def test_backup_kube_control_plane_backup_kube_static_pods_fail(self):
        """ The unit test covers the behavior of the method
            backup_kube_control_plane when backup_kube_static_pods raises
            an exception
        """
        mock_remove_kube_control_plane_backup = mock.MagicMock()
        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager.'
            'remove_kube_control_plane_backup',
            mock_remove_kube_control_plane_backup)
        p.start()
        self.addCleanup(p.stop)

        mock_backup_kube_static_pods = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.backup_kube_static_pods',
            mock_backup_kube_static_pods)
        p.start().side_effect = Exception("backup failed")
        self.addCleanup(p.stop)

        mock_etcd_snapshot_etcd = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.etcd.snapshot_etcd',
            mock_etcd_snapshot_etcd)
        p.start()
        self.addCleanup(p.stop)

        self.assertRaises(  # noqa: H202
            Exception,
            self.service.backup_kube_control_plane,
            self.context
        )
        mock_remove_kube_control_plane_backup.assert_called()
        mock_backup_kube_static_pods.assert_called()
        mock_etcd_snapshot_etcd.assert_not_called()

    def test_backup_kube_control_plane_etcd_snapshot_etcd_fail(self):
        """ The unit test covers the behavior of the method
            backup_kube_control_plane when snapshot_etcd
            raises an exception
        """
        mock_remove_kube_control_plane_backup = mock.MagicMock()
        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager.'
            'remove_kube_control_plane_backup',
            mock_remove_kube_control_plane_backup)
        p.start()
        self.addCleanup(p.stop)

        mock_backup_kube_static_pods = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.backup_kube_static_pods',
            mock_backup_kube_static_pods)
        p.start()
        self.addCleanup(p.stop)

        mock_etcd_snapshot_etcd = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.etcd.snapshot_etcd',
            mock_etcd_snapshot_etcd)
        p.start().side_effect = Exception("Failed to snapshot etcd")
        self.addCleanup(p.stop)

        self.assertRaises(  # noqa: H202
            Exception,
            self.service.backup_kube_control_plane,
            self.context
        )
        mock_remove_kube_control_plane_backup.assert_called()
        mock_backup_kube_static_pods.assert_called()
        mock_etcd_snapshot_etcd.assert_called()

    def test_remove_kube_control_plane_backup(self):
        """ The unit test covers success case of the method
            remove_kube_control_plane_backup
        """
        mock_shutil_rmtree = mock.MagicMock()
        p = mock.patch('shutil.rmtree', mock_shutil_rmtree)
        p.start()
        self.addCleanup(p.stop)

        mock_os_path_exists = mock.MagicMock()
        p = mock.patch('os.path.exists', mock_os_path_exists)
        p.start().return_value = True
        self.addCleanup(p.stop)

        self.service.remove_kube_control_plane_backup(self.context)
        mock_os_path_exists.assert_called_with(
            kubernetes.KUBE_CONTROL_PLANE_BACKUP_PATH)
        mock_shutil_rmtree.assert_called_with(
            kubernetes.KUBE_CONTROL_PLANE_BACKUP_PATH)

    def test_kube_post_application_update(self):
        # Create application
        dbutils.create_test_app(
            name='stx-openstack',
            app_version='1.0-19',
            manifest_name='manifest',
            manifest_file='stx-openstack.yaml',
            status='applied',
            active=True)

        # Create an upgrade
        from_version = 'v1.42.1'
        to_version = 'v1.43.1'
        utils.create_test_kube_upgrade(
            from_version=from_version,
            to_version=to_version,
            state=kubernetes.KUBE_UPGRADING_KUBELETS,
        )

        # Run post update
        self.service.kube_post_application_update(self.context, to_version)

        # Verify that the upgrade state was updated
        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state,
                         kubernetes.KUBE_POST_UPDATED_APPS)

    def test_kube_post_application_update_app_not_compatible(self):
        # Test post app update step when the installed application isn't
        # compatible with the new kubernetes version

        # Create application
        dbutils.create_test_app(
            name='stx-openstack',
            app_version='1.0-19',
            manifest_name='manifest',
            manifest_file='stx-openstack.yaml',
            status='applied',
            active=True)

        # Create an upgrade
        from_version = 'v1.42.1'
        to_version = 'v1.43.2'
        utils.create_test_kube_upgrade(
            from_version=from_version,
            to_version=to_version,
            state=kubernetes.KUBE_UPGRADING_KUBELETS,
        )

        # Run update
        self.service.kube_post_application_update(self.context, to_version)

        # Verify that the upgrade state was updated
        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state,
                         kubernetes.KUBE_POST_UPDATING_APPS_FAILED)

# @mock.patch('sysinv.conductor.manager.utils.HostHelper.get_active_controller')
# @mock.patch('sysinv.conductor.manager.'
#             'ConductorManager._config_apply_runtime_manifest')
# @mock.patch('sysinv.conductor.manager.'
#             'ConductorManager._config_update_hosts')
# @mock.patch('sysinv.db.sqlalchemy.api.Connection.runtime_config_get_all')
# @mock.patch('sysinv.db.sqlalchemy.api.Connection.runtime_config_update')
# def test_kube_upgrade_abort_kubeadm_process_kill(self, mock_runtime_config_update,
#                                             mock_runtime_config_get_all,
#                                             mock_config_update_hosts, mock_config_apply_runtime_manifest,
#                                             mock_get_active_controller):

#     mock_get_active_controller.return_value.uuid = "5e53976d-550d-452c-b018-1d37242ffdf9"
#     mock_config_update_hosts.return_value = "4e93a1c4-44c0-4cb8-839b-e50d166514d0"

#     mock_grandparent_proc = mock.MagicMock()
#     mock_grandparent_proc.info = {'pid': 32187, 'name': 'sysinv-conductor',
#                                   'cmdline': ['/bin/sysinv-conductor', '--config-file=/etc/sysinv/sysinv.conf']}
#     mock_grandparent_proc.cmdline.return_value = ['/bin/sysinv-conductor', '--config-file=/etc/sysinv/sysinv.conf']

#     mock_parent_proc = mock.MagicMock()
#     mock_parent_proc.info = {'pid': 5678, 'name': 'puppet', 'cmdline': ['puppet', 'apply']}
#     mock_parent_proc.cmdline.return_value = ['puppet', 'apply']
#     mock_parent_proc.parent.return_value = mock_grandparent_proc

#     mock_proc = mock.MagicMock()
#     mock_proc.info = {'pid': 1234, 'name': 'kubeadm', 'cmdline': ['kubeadm', 'upgrade']}
#     mock_proc.parent.return_value = mock_parent_proc
#     p = mock.patch('psutil.process_iter', mock_proc)
#     p.start().return_value = [mock_proc]
#     self.addCleanup(p.stop)

#     mock_proc.kill(mock_proc.info['pid'])
#     mock_proc.kill(mock_parent_proc.info['pid'])

#     mock_runtime_config_get_all.return_value = \
#         [mock.MagicMock(id=1, config_dict=json.dumps({
#             "classes": ["platform::kubernetes::upgrade_first_control_plane"]}))]

#     # Simulate the system update
#     system_dict = self.system.as_dict()
#     system_dict['system_mode'] = constants.SYSTEM_MODE_SIMPLEX
#     self.dbapi.isystem_update(self.system.uuid, system_dict)

#     # Create an upgrade
#     utils.create_test_kube_upgrade(
#         from_version='v1.42.1',
#         to_version='v1.42.2',
#         state=kubernetes.KUBE_UPGRADE_ABORTING,
#     )

#     # Create controller-0
#     config_uuid = str(uuid.uuid4())
#     self._create_test_ihost(
#         personality=constants.CONTROLLER,
#         hostname='controller-0',
#         uuid=str(uuid.uuid4()),
#         config_status=None,
#         config_applied=config_uuid,
#         config_target=config_uuid,
#         invprovision=constants.PROVISIONED,
#         administrative=constants.ADMIN_UNLOCKED,
#         operational=constants.OPERATIONAL_ENABLED,
#         availability=constants.AVAILABILITY_ONLINE,
#     )

#     # Patch os.path functions
#     mock_os_path_dirname = mock.MagicMock()
#     p = mock.patch('os.path.dirname', mock_os_path_dirname)
#     p.start().return_value = "/fake/path/"
#     self.addCleanup(p.stop)

#     mock_os_path_exists = mock.MagicMock()
#     p = mock.patch('os.path.exists', mock_os_path_exists)
#     p.start().return_value = True
#     self.addCleanup(p.stop)

#     # Call the function that handles the upgrade abort
#     self.service.kube_upgrade_abort(self.context, kubernetes.KUBE_UPGRADED_NETWORKING)

#     personalities = [constants.CONTROLLER]
#     config_dict = {
#         "personalities": personalities,
#         "classes": ['platform::kubernetes::upgrade_abort'],
#         puppet_common.REPORT_STATUS_CFG: puppet_common.REPORT_UPGRADE_ABORT
#     }

#     # Assert the expected calls
#     mock_proc.assert_called()
#     mock_proc.parent.assert_called()
#     mock_proc.kill.assert_has_calls([mock.call(mock_proc.info['pid']),
#                                      mock.call(mock_parent_proc.info['pid'])])
#     mock_runtime_config_update.assert_called_with(1, {"state": constants.RUNTIME_CONFIG_STATE_FAILED})
#     mock_config_apply_runtime_manifest.assert_called_with(mock.ANY, '4e93a1c4-44c0-4cb8-839b-e50d166514d0',
#                                                             config_dict)

# def test_handle_upgrade_abort_success(self):
#     utils.create_test_kube_upgrade(
#               from_version='v1.42.1',
#               to_version='v1.42.2',
#               state=kubernetes.KUBE_UPGRADE_ABORTING,
#               recovery_attempts=2
#     )
#     kube_upgrade_obj = objects.kube_upgrade.get_one(context)
#     self.service.handle_upgrade_abort_success(self.context,
#                                     kube_upgrade_obj)
#     self.assertEqual(kube_upgrade_obj.state,
#                      kubernetes.KUBE_UPGRADE_ABORTED)

    @mock.patch('os.listdir')
    @mock.patch('os.path.isdir', return_value=True)
    @mock.patch('sysinv.helm.helm.HelmOperator.discover_plugins', return_value=None)
    def test_kube_delete_container_images(self, mock_isdir, mock_listdir, mock_discover_plugins):
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )
        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version='v1.41.1',
            to_version='v1.43.1',
            state=kubernetes.KUBE_UPGRADE_COMPLETE,
        )

        mock_kube_get_lower_equal_versions = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_get_lower_equal_versions',
            mock_kube_get_lower_equal_versions)
        p.start().return_value = ['v1.41.1', 'v1.42.1', 'v1.42.2', 'v1.43.1']
        self.addCleanup(p.stop)

        mock_os_path_exists = mock.MagicMock()
        p = mock.patch('os.path.exists', mock_os_path_exists)
        p.start().return_value = True
        self.addCleanup(p.stop)

        mock_kube_docker_registry_image_delete = mock.Mock()
        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager.docker_registry_image_delete',
            mock_kube_docker_registry_image_delete)
        p.start().return_value = None
        self.addCleanup(p.stop)

        # get k8s versions lesser than and equal to target version
        next_versions = kubernetes.KubeOperator().kube_get_lower_equal_versions('v1.43.1')

        mock_subprocess = mock.MagicMock()
        p1 = mock.patch('subprocess.run', mock_subprocess)
        p1.start().returncode = 0
        self.addCleanup(p1.stop)

        mock_os_path_exists = mock.MagicMock()
        p = mock.patch('os.path.exists', mock_os_path_exists)
        p.start().return_value = True
        self.addCleanup(p.stop)

        self.service.start()
        self.service.kube_delete_container_images(self.context, 'v1.43.1')

        img_calls = []
        for version in next_versions:
            # verify that the command is run for each version
            kubeadm_version = version.lstrip('v')
            kubeadm_path = '/usr/local/kubernetes/{}/stage1/usr/bin/kubeadm'.format(kubeadm_version)
            cmd = [kubeadm_path, 'config', 'images', 'list', '--kubernetes-version', version]
            mock_subprocess(cmd)
            img_calls.append(mock.call(cmd))
        mock_subprocess.assert_has_calls(img_calls)

        fake_images = {'k8s.gcr.io/kube-apiserver:v1.23.1', 'k8s.gcr.io/pause:3.4.1',
                      'docker.io/intel/intel-gpu-initcontainer:0.26.0', 'k8s.gcr.io/kube-controller-manager:v1.23.1',
                      'k8s.gcr.io/etcd:3.4.13-0', 'k8s.gcr.io/kube-scheduler:v1.21.8',
                      'k8s.gcr.io/coredns/coredns:v1.8.4', 'k8s.gcr.io/kube-proxy:v1.22.5',
                      'k8s.gcr.io/kube-proxy:v1.23.1', 'k8s.gcr.io/pause:3.5', 'k8s.gcr.io/coredns/coredns:v1.8.6'}

        mk_calls = []
        for images in fake_images:
            # verify that docker_registry_images_delete function is called for all images in given set of fake images.
            mock_kube_docker_registry_image_delete(self.context, images)
            mk_calls.append(mock.call(self.context, images))

        mock_kube_docker_registry_image_delete.assert_has_calls(mk_calls, any_order=True)

    def test_sanitize_kubeadm_configmap(self):
        """
        This unit test covers the following use cases:
        1. a component with no 'extraArgs' field
        2. a component with an 'extraArgs' field but no 'feature-gates' entry
        3. a component with an 'extraArgs' field containing 'feature-gates'
           but no "RemoveSelfLink=false" entry.
        """
        mock_kube_read_config_map = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_read_config_map',
            mock_kube_read_config_map)
        p.start().return_value = self.kubeadm_config_read
        self.addCleanup(p.stop)

        mock_kube_patch_config_map = mock.MagicMock()
        p2 = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_patch_config_map',
            mock_kube_patch_config_map)
        p2.start().return_value = self.kubeadm_config_map_patch
        self.addCleanup(p2.stop)

        self.service.start()
        self.service.sanitize_kubeadm_configmap('v1.42.2')
        mock_kube_patch_config_map.assert_called_with(
                'kubeadm-config', 'kube-system', self.kubeadm_config_map_patch)

    def test_sanitize_kubeadm_configmap_etcd_endpoints(self):
        """
        This unit test covers the following use cases:
        1. configmap containing multiple etcd endpoints including loopback
           and specified target_version
        2. configmap containing multiple etcd endpoints including loopback
           and target_version None
        """
        mock_kube_read_config_map = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_read_config_map',
            mock_kube_read_config_map)
        p.start().return_value = self.kubeadm_config_map_read_etcd_endpoints
        self.addCleanup(p.stop)

        mock_kube_patch_config_map = mock.MagicMock()
        p2 = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_patch_config_map',
            mock_kube_patch_config_map)
        p2.start().return_value = self.kubeadm_config_map_patch_etcd_endpoints
        self.addCleanup(p2.stop)

        self.service.start()
        self.service.sanitize_kubeadm_configmap('v1.42.2')
        mock_kube_patch_config_map.assert_called_with(
                'kubeadm-config', 'kube-system', self.kubeadm_config_map_patch_etcd_endpoints)

        self.service.sanitize_kubeadm_configmap(None)
        mock_kube_patch_config_map.assert_called_with(
                'kubeadm-config', 'kube-system', self.kubeadm_config_map_patch_etcd_endpoints)

    def _create_test_controller_config_out_of_date(self, hostname):
        config_applied = self.service._config_set_reboot_required(uuid.uuid4())
        config_target = self.service._config_set_reboot_required(uuid.uuid4())
        ihost = self._create_test_ihost(
            uuid=str(uuid.uuid4()),
            config_applied=config_applied,
            config_target=config_target)
        ihost['mgmt_mac'] = '00:11:22:33:44:55'
        ihost['hostname'] = hostname
        ihost['invprovision'] = 'provisioned'
        ihost['personality'] = 'controller'
        ihost['administrative'] = 'unlocked'
        ihost['operational'] = 'disabled'
        ihost['availability'] = 'online'
        ihost['serialid'] = '1234567890abc'
        ihost['boot_device'] = 'sda'
        ihost['rootfs_device'] = 'sda'
        ihost['hw_settle'] = '0'
        ihost['sw_version'] = '0.0'
        ihost['install_output'] = 'text'
        ihost['console'] = 'ttyS0,115200'

        return ihost

    @mock.patch('os.path.isfile', return_value=True)
    @mock.patch('os.path.isdir', return_value=True)
    @mock.patch('shutil.copytree')
    @mock.patch('sysinv.conductor.manager.tempfile.mkdtemp', return_value='/tmp/mock-temp-dir')
    def test_configure_out_of_date(self, mock_mkdtemp, mock_copytree, mock_isdir, mock_isfile):
        cutils.is_aio_system = mock.Mock(return_value=True)
        ihost = self._create_test_controller_config_out_of_date('controller-0')
        self.service.configure_ihost(self.context, ihost)
        res = self.dbapi.ihost_get(ihost['uuid'])
        imsg_dict = {'config_applied': res['config_target']}
        self.service.iconfig_update_by_ihost(self.context, ihost['uuid'], imsg_dict)
        self.assertEqual(self.alarm_raised, False)

        personalities = [constants.CONTROLLER]
        self.service._config_update_hosts(self.context, personalities, reboot=True)
        res = self.dbapi.ihost_get(ihost['uuid'])

        personalities = [constants.CONTROLLER]
        self.service._config_update_hosts(self.context, personalities, reboot=False)
        res = self.dbapi.ihost_get(ihost['uuid'])
        config_uuid = self.service._config_clear_reboot_required(res['config_target'])
        imsg_dict = {'config_applied': config_uuid}
        self.service.iconfig_update_by_ihost(self.context, ihost['uuid'], imsg_dict)
        self.assertEqual(self.alarm_raised, True)

    @mock.patch('os.path.isfile', return_value=True)
    @mock.patch('os.path.isdir', return_value=True)
    @mock.patch('shutil.copytree')
    @mock.patch('sysinv.conductor.manager.tempfile.mkdtemp', return_value='/tmp/mock-temp-dir')
    def test_configure_out_of_date_upgrade(self, mock_mkdtemp, mock_copytree, mock_isdir, mock_isfile):
        cutils.is_aio_system = mock.Mock(return_value=True)

        # Check upgrade where the target sw_version does not match
        self.mock_host_load_matches_sw_version.return_value = False
        self.mock_usm_service_get_by_hostname.return_value = (
            usm_service.UsmHostUpgrade("controller-1", "0.0", "0.1", "host-pending"))
        ihost = self._create_test_controller_config_out_of_date('controller-1')
        self.service.configure_ihost(self.context, ihost)
        res = self.dbapi.ihost_get(ihost['uuid'])
        imsg_dict = {'config_applied': res['config_target']}
        self.service.iconfig_update_by_ihost(self.context, ihost['uuid'], imsg_dict)
        self.assertEqual(self.alarm_raised, False)

        personalities = [constants.CONTROLLER]
        self.service._config_update_hosts(self.context, personalities, reboot=True)
        res = self.dbapi.ihost_get(ihost['uuid'])

        personalities = [constants.CONTROLLER]
        self.service._config_update_hosts(self.context, personalities, reboot=False)
        res = self.dbapi.ihost_get(ihost['uuid'])
        config_uuid = self.service._config_clear_reboot_required(res['config_target'])
        imsg_dict = {'config_applied': config_uuid}
        self.service.iconfig_update_by_ihost(self.context, ihost['uuid'], imsg_dict)
        self.assertEqual(self.alarm_raised, True)

    def fake_rename(self, old, new):
        self.executes.append(('mv', old, new))

    @mock.patch('os.path.isdir', return_value=True)
    @mock.patch('shutil.copytree')
    @mock.patch('sysinv.conductor.manager.tempfile.mkdtemp', return_value='/tmp/mock-temp-dir')
    def test_deferred_runtime_config_file(self, mock_mkdtemp, mock_copytree, mock_isdir):

        # Create controller-0
        config_uuid = str(uuid.uuid4())
        chost = self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        # create test dns nameservers config
        utils.create_test_dns(forisystemid=self.system.id,
                              nameservers='8.8.8.8,8.8.4.4')
        cutils.gethostbyname = mock.Mock(return_value='192.168.204.2')

        self.executes = []
        self.stub_out('os.rename', self.fake_rename)

        # These mock for builtin open are needed for py27 and py3 compatibility
        mock_trace_caller = mock.MagicMock()
        p = mock.patch(
            'traceback.format_stack',
            mock_trace_caller)
        p.start()
        p.return_value = ['one', 'two', 'three']
        self.addCleanup(p.stop)

        self.mock_ready_to_apply_runtime_config.return_value = False
        self.service.update_dns_config(self.context)
        chost_updated = self.dbapi.ihost_get(chost.uuid)

        # Verify that the config is updated and alarm is raised
        self.assertNotEqual(chost_updated.config_applied,
                            chost_updated.config_target)
        self.assertEqual(self.alarm_raised, True)

        self.mock_ready_to_apply_runtime_config.return_value = True
        self.service._audit_deferred_runtime_config(self.context)

        # Simulate agent update
        chost_updated = self.dbapi.ihost_get(chost.uuid)
        self.service._update_host_config_applied(
            self.context, chost_updated, chost_updated.config_applied)

        # Verify the config is up to date.
        self.assertEqual(chost_updated.config_target,
                         chost_updated.config_applied)
        self.assertEqual(self.alarm_raised, False)

    @mock.patch('os.path.isdir', return_value=True)
    @mock.patch('shutil.copytree')
    @mock.patch('sysinv.conductor.manager.tempfile.mkdtemp', return_value='/tmp/mock-temp-dir')
    def test_deferred_runtime_config_manifest(self, mock_mkdtemp, mock_copytree, mock_isdir):
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        chost = self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        self.mock_ready_to_apply_runtime_config.return_value = False
        self.service.update_user_config(self.context)
        chost_updated = self.dbapi.ihost_get(chost.uuid)

        # Verify that the config is updated and alarm is raised
        self.assertNotEqual(chost_updated.config_applied,
                            chost_updated.config_target)
        self.assertEqual(self.alarm_raised, True)

        self.mock_ready_to_apply_runtime_config.return_value = True
        self.service._audit_deferred_runtime_config(self.context)

        # Simulate agent update
        chost_updated = self.dbapi.ihost_get(chost.uuid)
        self.service._update_host_config_applied(
            self.context, chost_updated, chost_updated.config_applied)

        # Verify the config is up to date.
        self.assertEqual(chost_updated.config_target,
                         chost_updated.config_applied)
        self.assertEqual(self.alarm_raised, False)

    @mock.patch('os.path.isdir', return_value=True)
    @mock.patch('shutil.copytree')
    @mock.patch('sysinv.conductor.manager.tempfile.mkdtemp', return_value='/tmp/mock-temp-dir')
    def test_deferred_multiple_runtime_config(self, mock_mkdtemp, mock_copytree, mock_isdir):
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        chost = self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        # create test dns nameservers config
        utils.create_test_dns(forisystemid=self.system.id,
                              nameservers='8.8.8.8,8.8.4.4')
        cutils.gethostbyname = mock.Mock(return_value='192.168.204.2')

        self.executes = []
        self.stub_out('os.rename', self.fake_rename)

        # These mock for builtin open are needed for py27 and py3 compatibility
        mock_trace_caller = mock.MagicMock()
        p = mock.patch(
            'traceback.format_stack',
            mock_trace_caller)
        p.start()
        p.return_value = ['one', 'two', 'three']
        self.addCleanup(p.stop)

        # Attempt to apply a runtime config, which is deferred
        self.mock_ready_to_apply_runtime_config.return_value = False
        self.service.update_dns_config(self.context)
        c1host_updated = self.dbapi.ihost_get(chost.uuid)

        # Verify that the config is updated and alarm is raised
        self.assertNotEqual(c1host_updated.config_applied,
                            c1host_updated.config_target)
        self.assertEqual(self.alarm_raised, True)

        # Attempt another runtime config, which is also deferred
        self.service.update_user_config(self.context)
        c2host_updated = self.dbapi.ihost_get(chost.uuid)

        # Verify that the target is updated and alarm is still raised
        self.assertNotEqual(c1host_updated.config_target,
                            c2host_updated.config_target)
        self.assertEqual(c1host_updated.config_applied,
                         c1host_updated.config_applied)
        self.assertNotEqual(c2host_updated.config_applied,
                            c2host_updated.config_target)
        self.assertEqual(self.alarm_raised, True)

        # Run the audit for deferred runtime config
        self.mock_ready_to_apply_runtime_config.return_value = True
        self.service._audit_deferred_runtime_config(self.context)

        # Simulate agent update
        chost_updated = self.dbapi.ihost_get(chost.uuid)
        self.service._update_host_config_applied(
            self.context, chost_updated, chost_updated.config_applied)

        # Verify the config is up to date.
        self.assertEqual(chost_updated.config_target,
                         chost_updated.config_applied)
        self.assertEqual(self.alarm_raised, False)

    def _raise_alarm(self, fault):
        self.alarm_raised = True

    def _clear_alarm(self, fm_id, fm_instance):
        self.alarm_raised = False

    def _get_faults_by_id(self, alarm_id):
        return None

    def _create_test_ihosts(self):
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            mgmt_mac='00:11:22:33:44:55')
        # Create controller-1
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-1',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            mgmt_mac='22:44:33:55:11:66')
        # Create compute-0
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.WORKER,
            hostname='compute-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            mgmt_mac='22:44:33:55:11:77')

    def _create_test_iports(self):
        enp25s0f0 = {'dev_id': 0, 'numa_node': 0, 'sriov_numvfs': 0, 'sriov_vfs_pci_address': '',
            'pdevice': 'Ethernet Controller X710 for 10GbE SFP+ [1572]', 'link_mode': '0',
            'driver': 'i40e', 'pclass': 'Ethernet controller [0200]', 'mtu': 1500,
            'psdevice': 'Ethernet Converged Network Adapter X710-2 [0008]',
            'mac': '3c:fd:fe:b5:72:e0', 'prevision': '-r01', 'sriov_vf_pdevice_id': None,
            'sriov_totalvfs': 64, 'pciaddr': '0000:19:00.0', 'dpdksupport': True,
            'pname': 'enp25s0f0', 'speed': 10000, 'psvendor': 'Intel Corporation [8086]',
            'sriov_vf_driver': None, 'pvendor': 'Intel Corporation [8086]'}
        enp25s0f1 = {'dev_id': 0, 'numa_node': 0, 'sriov_numvfs': 0, 'sriov_vfs_pci_address': '',
            'pdevice': 'Ethernet Controller X710 for 10GbE SFP+ [1572]', 'link_mode': '0',
            'driver': 'i40e', 'pclass': 'Ethernet controller [0200]', 'mtu': 1500,
            'psdevice': 'Ethernet Converged Network Adapter X710 [0000]',
            'mac': '3c:fd:fe:b5:72:e1', 'prevision': '-r01', 'sriov_vf_pdevice_id': None,
            'sriov_totalvfs': 64, 'pciaddr': '0000:19:00.1', 'dpdksupport': True,
            'pname': 'enp25s0f1', 'speed': 10000, 'psvendor': 'Intel Corporation [8086]',
            'sriov_vf_driver': None, 'pvendor': 'Intel Corporation [8086]'}
        enp134s0f0 = {'dev_id': 0, 'numa_node': 1, 'sriov_numvfs': 0, 'sriov_vfs_pci_address': '',
            'pdevice': '82571EB/82571GB Gigabit Ethernet Controller D0/D1 [105e]',
            'link_mode': '0', 'driver': 'e1000e', 'pclass': 'Ethernet controller [0200]',
            'mtu': 1500, 'psdevice': 'PRO/1000 PT Dual Port Server Adapter [115e]',
            'mac': '00:15:17:cd:c4:ac', 'prevision': '-r06', 'sriov_vf_pdevice_id': None,
            'sriov_totalvfs': None, 'pciaddr': '0000:86:00.0', 'dpdksupport': False,
            'pname': 'enp134s0f0', 'speed': None, 'psvendor': 'Intel Corporation [8086]',
            'sriov_vf_driver': None, 'pvendor': 'Intel Corporation [8086]'}
        enp134s0f1 = {'dev_id': 0, 'numa_node': 1, 'sriov_numvfs': 0, 'sriov_vfs_pci_address': '',
            'pdevice': '82571EB/82571GB Gigabit Ethernet Controller D0/D1 [105e]', 'link_mode': '0',
            'driver': 'e1000e', 'pclass': 'Ethernet controller [0200]',
            'mtu': 1500, 'psdevice': 'PRO/1000 PT Dual Port Server Adapter [115e]',
            'mac': '00:15:17:cd:c4:ad', 'prevision': '-r06', 'sriov_vf_pdevice_id': None,
            'sriov_totalvfs': None, 'pciaddr': '0000:86:00.1', 'dpdksupport': False,
            'pname': 'enp134s0f1', 'speed': 1000, 'psvendor': 'Intel Corporation [8086]',
            'sriov_vf_driver': None, 'pvendor': 'Intel Corporation [8086]'}
        enp135s0f0 = {'dev_id': 0, 'numa_node': 1, 'sriov_numvfs': 0, 'sriov_vfs_pci_address': '',
            'pdevice': 'Ethernet Controller X710 for 10GbE SFP+ [1572]', 'link_mode': '0',
            'driver': 'i40e', 'pclass': 'Ethernet controller [0200]', 'mtu': 9216,
            'psdevice': 'Ethernet Converged Network Adapter X710-2 [0008]',
            'mac': '3c:fd:fe:b5:73:28', 'prevision': '-r01', 'sriov_vf_pdevice_id': None,
            'sriov_totalvfs': 64, 'pciaddr': '0000:87:00.0', 'dpdksupport': True,
            'pname': 'enp135s0f0', 'speed': 10000, 'psvendor': 'Intel Corporation [8086]',
            'sriov_vf_driver': None, 'pvendor': 'Intel Corporation [8086]'}
        enp135s0f1 = {'dev_id': 0, 'numa_node': 1, 'sriov_numvfs': 0, 'sriov_vfs_pci_address': '',
            'pdevice': 'Ethernet Controller X710 for 10GbE SFP+ [1572]', 'link_mode': '0',
            'driver': 'i40e', 'pclass': 'Ethernet controller [0200]', 'mtu': 1500,
            'psdevice': 'Ethernet Converged Network Adapter X710 [0000]',
            'mac': '3c:fd:fe:b5:73:29', 'prevision': '-r01', 'sriov_vf_pdevice_id': None,
            'sriov_totalvfs': 64, 'pciaddr': '0000:87:00.1', 'dpdksupport': True,
            'pname': 'enp135s0f1', 'speed': None, 'psvendor': 'Intel Corporation [8086]',
            'sriov_vf_driver': None, 'pvendor': 'Intel Corporation [8086]'}
        enp177s0f0 = {'dev_id': 0, 'numa_node': 1, 'sriov_numvfs': 0, 'sriov_vfs_pci_address': '',
            'pdevice': 'Device [0d58]', 'link_mode': '0', 'driver': 'i40e',
            'pclass': 'Ethernet controller [0200]', 'mtu': 1500, 'psdevice': 'Device [0000]',
            'mac': '64:4c:36:12:9b:78', 'prevision': '-r02', 'sriov_vf_pdevice_id': None,
            'sriov_totalvfs': 64, 'pciaddr': '0000:b1:00.0', 'dpdksupport': False,
            'pname': 'enp177s0f0', 'speed': None, 'psvendor': 'Intel Corporation [8086]',
            'sriov_vf_driver': None, 'pvendor': 'Intel Corporation [8086]'}
        enp177s0f1 = {'dev_id': 0, 'numa_node': 1, 'sriov_numvfs': 0, 'sriov_vfs_pci_address': '',
            'pdevice': 'Device [0d58]', 'link_mode': '0', 'driver': 'i40e',
            'pclass': 'Ethernet controller [0200]', 'mtu': 1500, 'psdevice': 'Device [0000]',
            'mac': '64:4c:36:12:9b:79', 'prevision': '-r02', 'sriov_vf_pdevice_id': None,
            'sriov_totalvfs': 64, 'pciaddr': '0000:b1:00.1', 'dpdksupport': False,
            'pname': 'enp177s0f1', 'speed': None, 'psvendor': 'Intel Corporation [8086]',
            'sriov_vf_driver': None, 'pvendor': 'Intel Corporation [8086]'}
        enp181s0f0 = {'dev_id': 0, 'numa_node': 1, 'sriov_numvfs': 0, 'sriov_vfs_pci_address': '',
            'pdevice': 'Device [0d58]', 'link_mode': '0', 'driver': 'i40e',
            'pclass': 'Ethernet controller [0200]', 'mtu': 1500, 'psdevice': 'Device [0000]',
            'mac': '64:4c:36:12:9b:7c', 'prevision': '-r02', 'sriov_vf_pdevice_id': None,
            'sriov_totalvfs': 64, 'pciaddr': '0000:b3:00.0', 'dpdksupport': False,
            'pname': 'enp181s0f0', 'speed': None, 'psvendor': 'Intel Corporation [8086]',
            'sriov_vf_driver': None, 'pvendor': 'Intel Corporation [8086]'}
        enp181s0f1 = {'dev_id': 0, 'numa_node': 1, 'sriov_numvfs': 0, 'sriov_vfs_pci_address': '',
            'pdevice': 'Device [0d58]', 'link_mode': '0', 'driver': 'i40e',
            'pclass': 'Ethernet controller [0200]', 'mtu': 1500, 'psdevice': 'Device [0000]',
            'mac': '64:4c:36:12:9b:7d', 'prevision': '-r02', 'sriov_vf_pdevice_id': None,
            'sriov_totalvfs': 64, 'pciaddr': '0000:b3:00.1', 'dpdksupport': False,
            'pname': 'enp181s0f1', 'speed': None, 'psvendor': 'Intel Corporation [8086]',
            'sriov_vf_driver': None, 'pvendor': 'Intel Corporation [8086]'}

        inic_dict_array = [enp25s0f0, enp25s0f1, enp134s0f0, enp134s0f1,
            enp135s0f0, enp135s0f1, enp177s0f0, enp177s0f1, enp181s0f0, enp181s0f1]

        return inic_dict_array

    def _create_test_iports_with_new_macs(self, ei_inc):
        # New MAC addresses created by incrementing the the original EI first byte by ei_inc
        # Example: ei_inc=2 , 3c:fd:fe:b5:72:e0 -> 3c:fd:fe:b7:72:e0
        new_inic_dict_array = self._create_test_iports()
        for inic in new_inic_dict_array:
            mac = netaddr.EUI(inic['mac'])
            new_mac = netaddr.EUI(int(mac) + (ei_inc << 16), dialect=netaddr.mac_unix_expanded)
            inic['mac'] = str(new_mac)
        return new_inic_dict_array

    def _create_test_networks(self, mgmt_vlan_id):
        address_pool_mgmt = utils.create_test_address_pool(id=1, network='192.168.204.0',
            name='management', ranges=[['192.168.204.2', '192.168.204.254']], prefix=24)
        mgmt_net = utils.create_test_network(id=1, name='mgmt', type=constants.NETWORK_TYPE_MGMT,
            link_capacity=1000, vlan_id=mgmt_vlan_id, address_pool_id=address_pool_mgmt.id)

        address_pool_pxeboot = utils.create_test_address_pool(id=2, network='192.168.205.0',
            name='pxeboot', ranges=[['192.168.205.2', '192.168.205.254']], prefix=24)
        pxeboot_net = utils.create_test_network(id=2, name='pxeboot',
            type=constants.NETWORK_TYPE_PXEBOOT,
            link_capacity=1000, address_pool_id=address_pool_pxeboot.id)

        return mgmt_net, pxeboot_net

    def test_get_ihost_by_macs(self):
        self._create_test_ihosts()
        mgmt_net, pxeboot_net = self._create_test_networks(0)
        address = {'name': 'controller-1-mgmt',
                   'family': 4,
                   'prefix': 24,
                   'address': '192.168.204.3'}
        utils.create_test_address(**address)
        ihost_macs = ['22:44:33:55:11:66', '22:44:33:88:11:66']
        ihost = self.service.get_ihost_by_macs(self.context, ihost_macs)
        self.assertEqual(ihost.mgmt_mac, '22:44:33:55:11:66')

    def test_get_ihost_by_macs_no_match(self):
        self._create_test_ihosts()
        ihost = None
        ihost_macs = ['22:44:33:99:11:66', '22:44:33:88:11:66']
        ihost = self.service.get_ihost_by_macs(self.context, ihost_macs)
        self.assertEqual(ihost, None)

    def test_get_ihost_by_hostname(self):
        self._create_test_ihosts()
        ihost_hostname = 'controller-1'
        ihost = self.service.get_ihost_by_hostname(self.context, ihost_hostname)
        self.assertEqual(ihost.mgmt_mac, '22:44:33:55:11:66')
        self.assertEqual(ihost.hostname, 'controller-1')

    def test_get_ihost_by_hostname_invalid_name(self):
        self._create_test_ihosts()
        ihost_hostname = 'compute'
        ihost = None
        ihost = self.service.get_ihost_by_hostname(self.context, ihost_hostname)
        self.assertEqual(ihost, None)

    def test_iport_update_by_ihost_basic_creation(self):
        """Test the sysinv-agent port inventory basic port and interface creation

        This test creates the port and interfaces based on the incoming report without any entry
        matching the MAC address. The objective of this test if the data is stored on the correct
        database tables
        """
        # Create compute-0 node
        config_uuid = str(uuid.uuid4())
        ihost = self._create_test_ihost(
            hostname='compute-0', mgmt_mac='22:44:33:55:11:77', uuid=str(uuid.uuid4()),
            personality=constants.WORKER, config_status=None, config_applied=config_uuid,
            config_target=config_uuid, invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED, operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        mock_find_local_mgmt_interface_vlan_id = mock.MagicMock()
        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager._find_local_mgmt_interface_vlan_id',
            mock_find_local_mgmt_interface_vlan_id)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_socket_gethostname = mock.MagicMock()
        p2 = mock.patch('socket.gethostname', mock_socket_gethostname)
        p2.start().return_value = 'controller-0'
        self.addCleanup(p2.stop)

        inic_dict_array = self._create_test_iports()

        inic_mac_dict = dict()
        for inic in inic_dict_array:
            inic_mac_dict[inic['mac']] = inic

        inic_pciaddr_dict = dict()
        for inic in inic_dict_array:
            inic_pciaddr_dict[inic['pciaddr']] = inic

        self.service.iport_update_by_ihost(self.context, ihost['uuid'], inic_dict_array)

        # check fields for each table
        iface_db_list = self.dbapi.iinterface_get_by_ihost(ihost['uuid'])
        self.assertEqual(len(iface_db_list), len(inic_dict_array))
        for iface in iface_db_list:
            self.assertIn(iface.imac, inic_mac_dict)
            self.assertEqual(inic_mac_dict[iface.imac]['pname'], iface.ifname)
            self.assertEqual(inic_mac_dict[iface.imac]['mac'], iface.imac)

        eth_iface_db_list = self.dbapi.ethernet_interface_get_by_ihost(ihost['uuid'])
        self.assertEqual(len(eth_iface_db_list), len(inic_dict_array))

        port_db_list = self.dbapi.port_get_by_host(ihost['uuid'])
        self.assertEqual(len(port_db_list), len(inic_dict_array))
        for port in port_db_list:
            self.assertIn(port.pciaddr, inic_pciaddr_dict)
            self.assertEqual(inic_pciaddr_dict[port.pciaddr]['pciaddr'], port.pciaddr)
            self.assertEqual(inic_pciaddr_dict[port.pciaddr]['pname'], port.name)
            self.assertEqual(inic_pciaddr_dict[port.pciaddr]['numa_node'], port.numa_node)
            self.assertEqual(inic_pciaddr_dict[port.pciaddr]['pdevice'], port.pdevice)
            self.assertEqual(inic_pciaddr_dict[port.pciaddr]['driver'], port.driver)
            self.assertEqual(inic_pciaddr_dict[port.pciaddr]['pclass'], port.pclass)
            self.assertEqual(inic_pciaddr_dict[port.pciaddr]['psdevice'], port.psdevice)
            self.assertEqual(inic_pciaddr_dict[port.pciaddr]['psvendor'], port.psvendor)
            self.assertEqual(inic_pciaddr_dict[port.pciaddr]['pvendor'], port.pvendor)
            self.assertEqual(inic_pciaddr_dict[port.pciaddr]['sriov_vf_driver'],
                            port.sriov_vf_driver)
            self.assertEqual(inic_pciaddr_dict[port.pciaddr]['sriov_numvfs'], port.sriov_numvfs)
            self.assertEqual(inic_pciaddr_dict[port.pciaddr]['sriov_totalvfs'], port.sriov_totalvfs)
            self.assertEqual(inic_pciaddr_dict[port.pciaddr]['sriov_vfs_pci_address'],
                            port.sriov_vfs_pci_address)
            self.assertEqual(inic_pciaddr_dict[port.pciaddr]['sriov_vf_pdevice_id'],
                            port.sriov_vf_pdevice_id)

        eth_port_db_list = self.dbapi.ethernet_port_get_by_host(ihost['uuid'])
        self.assertEqual(len(eth_port_db_list), len(inic_dict_array))
        for port in eth_port_db_list:
            self.assertEqual(inic_pciaddr_dict[port.pciaddr]['mtu'], port.mtu)
            self.assertEqual(inic_pciaddr_dict[port.pciaddr]['speed'], port.speed)
            self.assertEqual(inic_pciaddr_dict[port.pciaddr]['link_mode'], port.link_mode)

    def test_iport_update_by_ihost_report_with_mgmt_untagged(self):
        """Test the sysinv-agent port inventory for managemet interface without VLAN

        If the port MAC matches the host's MAC and it is not the active controller, test the entry
        update to become a managemet interface and attached to the management network. The port
        must receive the bootp flag.
        """
        mgmt_vlan_id = 0
        # Create compute-0 node
        config_uuid = str(uuid.uuid4())
        ihost = self._create_test_ihost(
            hostname='compute-0', mgmt_mac='22:44:33:55:11:77', uuid=str(uuid.uuid4()),
            personality=constants.WORKER, config_status=None, config_applied=config_uuid,
            config_target=config_uuid, invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED, operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )
        self._create_test_networks(mgmt_vlan_id)

        mock_find_local_mgmt_interface_vlan_id = mock.MagicMock()
        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager._find_local_mgmt_interface_vlan_id',
            mock_find_local_mgmt_interface_vlan_id)
        p.start().return_value = mgmt_vlan_id
        self.addCleanup(p.stop)

        mock_socket_gethostname = mock.MagicMock()
        p2 = mock.patch('socket.gethostname', mock_socket_gethostname)
        p2.start().return_value = 'controller-0'
        self.addCleanup(p2.stop)

        inic_dict_array = self._create_test_iports()
        inic_dict_array[2]['mac'] = ihost['mgmt_mac']

        self.service.iport_update_by_ihost(self.context, ihost['uuid'], inic_dict_array)

        iface_db_list = self.dbapi.iinterface_get_by_ihost(ihost['uuid'])
        self.assertEqual(len(iface_db_list), len(inic_dict_array))
        has_mgmt = False
        for iface in iface_db_list:
            if (iface.imac == ihost['mgmt_mac']):
                self.assertEqual('mgmt0', iface.ifname)
                self.assertEqual('ethernet', iface.iftype)
                self.assertEqual('platform', iface.ifclass)
                ifnets = self.dbapi.interface_network_get_by_interface(iface.uuid)
                self.assertEqual(len(ifnets), 1)
                network = self.dbapi.network_get_by_id(ifnets[0].network_id)
                self.assertEqual(network.type, constants.NETWORK_TYPE_MGMT)
                has_mgmt = True
        self.assertTrue(has_mgmt)

        eth_port_db_list = self.dbapi.ethernet_port_get_by_host(ihost['uuid'])
        for eth_port in eth_port_db_list:
            if (eth_port.mac == ihost['mgmt_mac']):
                self.assertTrue(eth_port.bootp)
            else:
                self.assertFalse(eth_port.bootp)

    def test_iport_update_by_ihost_report_with_mgmt_vlan(self):
        """Test the sysinv-agent port inventory for managemet interface with VLAN

        If the port MAC matches the host's MAC and it is not the active controller, there should
        be 2 interfaces with the same MAC, one without VLAN and marked for pxeboot usage and the
        other for management on the selected VLAN. The port must receive the bootp flag.
        """
        mgmt_vlan_id = 111
        # Create compute-0 node
        config_uuid = str(uuid.uuid4())
        ihost = self._create_test_ihost(
            hostname='compute-0', mgmt_mac='22:44:33:55:11:77', uuid=str(uuid.uuid4()),
            personality=constants.WORKER, config_status=None, config_applied=config_uuid,
            config_target=config_uuid, invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED, operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )
        self._create_test_networks(mgmt_vlan_id)

        mock_find_local_mgmt_interface_vlan_id = mock.MagicMock()
        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager._find_local_mgmt_interface_vlan_id',
            mock_find_local_mgmt_interface_vlan_id)
        p.start().return_value = mgmt_vlan_id
        self.addCleanup(p.stop)

        mock_socket_gethostname = mock.MagicMock()
        p2 = mock.patch('socket.gethostname', mock_socket_gethostname)
        p2.start().return_value = 'controller-0'
        self.addCleanup(p2.stop)

        inic_dict_array = self._create_test_iports()
        inic_dict_array[2]['mac'] = ihost['mgmt_mac']

        self.service.iport_update_by_ihost(self.context, ihost['uuid'], inic_dict_array)

        iface_db_list = self.dbapi.iinterface_get_by_ihost(ihost['uuid'])
        self.assertEqual(len(iface_db_list), len(inic_dict_array) + 1)
        has_mgmt = False
        has_pxeboot = False
        for iface in iface_db_list:
            if (iface.imac == ihost['mgmt_mac']):
                ifnets = self.dbapi.interface_network_get_by_interface(iface.uuid)
                if ('mgmt0' == iface.ifname):
                    self.assertEqual('vlan', iface.iftype)
                    self.assertEqual('platform', iface.ifclass)
                    self.assertEqual(mgmt_vlan_id, iface.vlan_id)
                    self.assertIn('mgmt', iface.networktypelist)
                    self.assertIn('pxeboot0', iface.uses)
                    has_mgmt = True
                    self.assertEqual(len(ifnets), 1)
                    network = self.dbapi.network_get_by_id(ifnets[0].network_id)
                    self.assertEqual(network.type, constants.NETWORK_TYPE_MGMT)
                if ('pxeboot0' == iface.ifname):
                    self.assertEqual('ethernet', iface.iftype)
                    self.assertEqual('platform', iface.ifclass)
                    self.assertIn('mgmt0', iface.used_by)
                    has_pxeboot = True
                    self.assertEqual(len(ifnets), 1)
                    network = self.dbapi.network_get_by_id(ifnets[0].network_id)
                    self.assertEqual(network.type, constants.NETWORK_TYPE_PXEBOOT)
        self.assertTrue(has_pxeboot and has_mgmt)

        eth_port_db_list = self.dbapi.ethernet_port_get_by_host(ihost['uuid'])
        for eth_port in eth_port_db_list:
            if (eth_port.mac == ihost['mgmt_mac']):
                self.assertTrue(eth_port.bootp)
            else:
                self.assertFalse(eth_port.bootp)

    def test_iport_update_by_ihost_report_active_controller_with_mgmt_untagged(self):
        """Test the port inventory for managemet interface without VLAN on the active controller

        If the port MAC matches the host's MAC and it is the active controller, no managemet
        interface is created and the port receive the bootp flag
        """
        mgmt_vlan_id = 0
        # Create controller-0 node
        config_uuid = str(uuid.uuid4())
        ihost = self._create_test_ihost(
            personality=constants.CONTROLLER, hostname='controller-0', uuid=str(uuid.uuid4()),
            config_status=None, config_applied=config_uuid, config_target=config_uuid,
            invprovision=constants.PROVISIONED, administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED, availability=constants.AVAILABILITY_ONLINE,
            mgmt_mac='00:11:22:33:44:55')
        self._create_test_networks(mgmt_vlan_id)

        mock_find_local_mgmt_interface_vlan_id = mock.MagicMock()
        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager._find_local_mgmt_interface_vlan_id',
            mock_find_local_mgmt_interface_vlan_id)
        p.start().return_value = mgmt_vlan_id
        self.addCleanup(p.stop)

        mock_socket_gethostname = mock.MagicMock()
        p2 = mock.patch('socket.gethostname', mock_socket_gethostname)
        p2.start().return_value = 'controller-0'
        self.addCleanup(p2.stop)

        inic_dict_array = self._create_test_iports()
        inic_dict_array[2]['mac'] = ihost['mgmt_mac']

        self.service.iport_update_by_ihost(self.context, ihost['uuid'], inic_dict_array)

        iface_db_list = self.dbapi.iinterface_get_by_ihost(ihost['uuid'])
        for iface in iface_db_list:
            if (iface.imac == ihost['mgmt_mac']):
                self.assertNotEqual('mgmt0', iface.ifname)
                self.assertNotEqual('platform', iface.ifclass)
                ifnets = self.dbapi.interface_network_get_by_interface(iface.uuid)
                self.assertEqual(len(ifnets), 0)

        eth_port_db_list = self.dbapi.ethernet_port_get_by_host(ihost['uuid'])
        for eth_port in eth_port_db_list:
            if (eth_port.mac == ihost['mgmt_mac']):
                self.assertTrue(eth_port.bootp)

    def test_iport_update_by_ihost_report_install_from_clone(self):
        """Test the port inventory MAC update when DB is in install from clone

        When installing from clone the database interfaces will have the MAC filed with a special
        marker, the inventory report will be used to update with the actual port MAC.
        """
        mgmt_vlan_id = 111
        inic_dict_array = self._create_test_iports()
        hostname = 'compute-0'
        clone_mgmt_mac = (constants.CLONE_ISO_MAC + hostname + inic_dict_array[3]['pname'])
        # Create compute-0 node
        config_uuid = str(uuid.uuid4())
        ihost = self._create_test_ihost(
            hostname=hostname, mgmt_mac=clone_mgmt_mac, uuid=str(uuid.uuid4()),
            personality=constants.WORKER, config_status=None, config_applied=config_uuid,
            config_target=config_uuid, invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED, operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )
        self._create_test_networks(mgmt_vlan_id)

        mock_find_local_mgmt_interface_vlan_id = mock.MagicMock()
        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager._find_local_mgmt_interface_vlan_id',
            mock_find_local_mgmt_interface_vlan_id)
        p.start().return_value = mgmt_vlan_id
        self.addCleanup(p.stop)

        mock_socket_gethostname = mock.MagicMock()
        p2 = mock.patch('socket.gethostname', mock_socket_gethostname)
        p2.start().return_value = 'controller-0'
        self.addCleanup(p2.stop)

        sriov0 = utils.create_test_interface(ifname='sriov0',
                                    forihostid=ihost.id, ihost_uuid=ihost.uuid,
                                    iftype=constants.INTERFACE_TYPE_ETHERNET,
                                    ifclass=constants.INTERFACE_CLASS_PCI_SRIOV,
                                    imac=(constants.CLONE_ISO_MAC + ihost['hostname']
                                          + inic_dict_array[0]['pname']))
        sriov0a = utils.create_test_interface(ifname='sriov0a',
                                    forihostid=ihost.id, ihost_uuid=ihost.uuid,
                                    iftype=constants.INTERFACE_TYPE_VF, uses=['sriov0'],
                                    ifclass=constants.INTERFACE_CLASS_PCI_SRIOV,
                                    imac=(constants.CLONE_ISO_MAC + ihost['hostname']
                                          + inic_dict_array[0]['pname']))
        data0 = utils.create_test_interface(ifname='data0',
                                    forihostid=ihost.id, ihost_uuid=ihost.uuid,
                                    ifclass=constants.INTERFACE_CLASS_DATA,
                                    imac=(constants.CLONE_ISO_MAC + ihost['hostname']
                                          + inic_dict_array[1]['pname']))
        pcipt0 = utils.create_test_interface(ifname='pcipt0',
                                    forihostid=ihost.id, ihost_uuid=ihost.uuid,
                                    ifclass=constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                                    imac=(constants.CLONE_ISO_MAC + ihost['hostname']
                                          + inic_dict_array[2]['pname']))
        pxeboot0 = utils.create_test_interface(ifname='pxeboot0',
                                    forihostid=ihost.id, ihost_uuid=ihost.uuid,
                                    iftype=constants.INTERFACE_TYPE_ETHERNET,
                                    ifclass=constants.INTERFACE_CLASS_PLATFORM,
                                    imac=clone_mgmt_mac)
        mgmt0 = utils.create_test_interface(ifname='mgmt0',
                                    forihostid=ihost.id, ihost_uuid=ihost.uuid,
                                    iftype=constants.INTERFACE_TYPE_VLAN, uses=['pxeboot0'],
                                    ifclass=constants.INTERFACE_CLASS_PLATFORM,
                                    vlan_id=mgmt_vlan_id, imac=clone_mgmt_mac)
        extra0 = utils.create_test_interface(ifname='extra0',
                                    forihostid=ihost.id, ihost_uuid=ihost.uuid,
                                    iftype=constants.INTERFACE_TYPE_VLAN, uses=['mgmt0'],
                                    ifclass=constants.INTERFACE_CLASS_PLATFORM,
                                    vlan_id=1001, imac=clone_mgmt_mac)
        extra1 = utils.create_test_interface(ifname='extra1',
                                    forihostid=ihost.id, ihost_uuid=ihost.uuid,
                                    iftype=constants.INTERFACE_TYPE_VLAN, uses=['mgmt0'],
                                    ifclass=constants.INTERFACE_CLASS_PLATFORM,
                                    vlan_id=1001, imac=clone_mgmt_mac)

        self.service.iport_update_by_ihost(self.context, ihost['uuid'], inic_dict_array)

        self.assertEqual(self.dbapi.iinterface_get(sriov0.id).imac, inic_dict_array[0]['mac'])
        self.assertEqual(self.dbapi.iinterface_get(sriov0a.id).imac, inic_dict_array[0]['mac'])
        self.assertEqual(self.dbapi.iinterface_get(data0.id).imac, inic_dict_array[1]['mac'])
        self.assertEqual(self.dbapi.iinterface_get(pcipt0.id).imac, inic_dict_array[2]['mac'])
        self.assertEqual(self.dbapi.iinterface_get(pxeboot0.id).imac, inic_dict_array[3]['mac'])
        self.assertEqual(self.dbapi.iinterface_get(mgmt0.id).imac, inic_dict_array[3]['mac'])
        self.assertEqual(self.dbapi.iinterface_get(extra0.id).imac, inic_dict_array[3]['mac'])
        self.assertEqual(self.dbapi.iinterface_get(extra1.id).imac, inic_dict_array[3]['mac'])

        self.assertEqual(self.dbapi.ihost_get_by_hostname(hostname).mgmt_mac,
                         inic_dict_array[3]['mac'])

    def test_iport_update_by_ihost_report_update(self):
        """Test the port inventory update

        Some port fields can be updated from the inventory report after database creation
        """
        # Create compute-0 node
        config_uuid = str(uuid.uuid4())
        ihost = self._create_test_ihost(
            hostname='compute-0', mgmt_mac='22:44:33:55:11:77', uuid=str(uuid.uuid4()),
            personality=constants.WORKER, config_status=None, config_applied=config_uuid,
            config_target=config_uuid, invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED, operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        mock_find_local_mgmt_interface_vlan_id = mock.MagicMock()
        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager._find_local_mgmt_interface_vlan_id',
            mock_find_local_mgmt_interface_vlan_id)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_socket_gethostname = mock.MagicMock()
        p2 = mock.patch('socket.gethostname', mock_socket_gethostname)
        p2.start().return_value = 'controller-0'
        self.addCleanup(p2.stop)

        inic_dict_array = self._create_test_iports()
        self.service.iport_update_by_ihost(self.context, ihost['uuid'], inic_dict_array)

        inic_dict_array[-1]['pname'] = 'new_centos_name'
        inic_dict_array[-1]['sriov_totalvfs'] = 32
        inic_dict_array[-1]['sriov_numvfs'] = 4
        inic_dict_array[-1]['sriov_vfs_pci_address'] = \
                             '0000:b1:02.0,0000:b1:02.1,0000:b1:02.2,0000:b1:02.3'
        inic_dict_array[-1]['sriov_vf_driver'] = 'iavf'
        inic_dict_array[-1]['sriov_vf_pdevice_id'] = '254c'
        inic_dict_array[-1]['driver'] = 'igb'
        inic_dict_array[-1]['dpdksupport'] = True
        inic_dict_array[-1]['speed'] = 5000

        self.service.iport_update_by_ihost(self.context, ihost['uuid'], inic_dict_array)

        db_size = len(inic_dict_array)
        self.assertEqual(len(self.dbapi.iinterface_get_by_ihost(ihost['uuid'])), db_size)
        self.assertEqual(len(self.dbapi.ethernet_interface_get_by_ihost(ihost['uuid'])), db_size)
        self.assertEqual(len(self.dbapi.port_get_by_host(ihost['uuid'])), db_size)
        self.assertEqual(len(self.dbapi.ethernet_port_get_by_host(ihost['uuid'])), db_size)

        port = self.dbapi.ethernet_port_get_by_mac(inic_dict_array[-1]['mac'])
        self.assertEqual(port.name, inic_dict_array[-1]['pname'])
        self.assertEqual(port.sriov_totalvfs, inic_dict_array[-1]['sriov_totalvfs'])
        self.assertEqual(port.sriov_numvfs, inic_dict_array[-1]['sriov_numvfs'])
        self.assertEqual(port.sriov_vfs_pci_address, inic_dict_array[-1]['sriov_vfs_pci_address'])
        self.assertEqual(port.sriov_vf_driver, inic_dict_array[-1]['sriov_vf_driver'])
        self.assertEqual(port.sriov_vf_pdevice_id, inic_dict_array[-1]['sriov_vf_pdevice_id'])
        self.assertEqual(port.sriov_totalvfs, inic_dict_array[-1]['sriov_totalvfs'])
        self.assertEqual(port.driver, inic_dict_array[-1]['driver'])
        self.assertEqual(port.speed, inic_dict_array[-1]['speed'])
        self.assertEqual(port.dpdksupport, inic_dict_array[-1]['dpdksupport'])

    def _create_test_interfaces(self, ihost, inic_dict_array, test_mgmt_mac, mgmt_vlan_id):
        ifaces = dict()
        ports = dict()
        ifaces['sriov0'] = utils.create_test_interface(ifname='sriov0',
                                    forihostid=ihost.id, ihost_uuid=ihost.uuid,
                                    iftype=constants.INTERFACE_TYPE_ETHERNET,
                                    ifclass=constants.INTERFACE_CLASS_PCI_SRIOV,
                                    imac=inic_dict_array[0]['mac'])
        ports['sriov0'] = utils.create_test_ethernet_port(name=inic_dict_array[0]['pname'],
                                    host_id=ihost.id, interface_id=ifaces['sriov0'].id,
                                    mac=inic_dict_array[0]['mac'],
                                    pciaddr=inic_dict_array[0]['pciaddr'],
                                    pdevice=inic_dict_array[0]['pdevice'],
                                    pvendor=inic_dict_array[0]['pvendor'])
        ifaces['sriov0a'] = utils.create_test_interface(ifname='sriov0a',
                                    forihostid=ihost.id, ihost_uuid=ihost.uuid,
                                    iftype=constants.INTERFACE_TYPE_VF, uses=['sriov0'],
                                    ifclass=constants.INTERFACE_CLASS_PCI_SRIOV,
                                    imac=inic_dict_array[0]['mac'])

        ifaces['data0'] = utils.create_test_interface(ifname='data0',
                                    forihostid=ihost.id, ihost_uuid=ihost.uuid,
                                    ifclass=constants.INTERFACE_CLASS_DATA,
                                    imac=inic_dict_array[1]['mac'])
        ports['data0'] = utils.create_test_ethernet_port(name=inic_dict_array[1]['pname'],
                                    host_id=ihost.id, interface_id=ifaces['data0'].id,
                                    mac=inic_dict_array[1]['mac'],
                                    pciaddr=inic_dict_array[1]['pciaddr'],
                                    pdevice=inic_dict_array[1]['pdevice'],
                                    pvendor=inic_dict_array[1]['pvendor'])

        ifaces['pcipt0'] = utils.create_test_interface(ifname='pcipt0',
                                    forihostid=ihost.id, ihost_uuid=ihost.uuid,
                                    ifclass=constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                                    imac=inic_dict_array[2]['mac'])
        ports['pcipt0'] = utils.create_test_ethernet_port(name=inic_dict_array[1]['pname'],
                                    host_id=ihost.id, interface_id=ifaces['pcipt0'].id,
                                    mac=inic_dict_array[2]['mac'],
                                    pciaddr=inic_dict_array[2]['pciaddr'],
                                    pdevice=inic_dict_array[2]['pdevice'],
                                    pvendor=inic_dict_array[2]['pvendor'])

        ifaces['pxeboot0'] = utils.create_test_interface(ifname='pxeboot0',
                                    forihostid=ihost.id, ihost_uuid=ihost.uuid,
                                    iftype=constants.INTERFACE_TYPE_ETHERNET,
                                    ifclass=constants.INTERFACE_CLASS_PLATFORM,
                                    imac=test_mgmt_mac)
        ports['pxeboot0'] = utils.create_test_ethernet_port(name=inic_dict_array[3]['pname'],
                                    host_id=ihost.id, interface_id=ifaces['pxeboot0'].id,
                                    mac=inic_dict_array[3]['mac'],
                                    pciaddr=inic_dict_array[3]['pciaddr'],
                                    pdevice=inic_dict_array[3]['pdevice'],
                                    pvendor=inic_dict_array[3]['pvendor'])
        ifaces['mgmt0'] = utils.create_test_interface(ifname='mgmt0',
                                    forihostid=ihost.id, ihost_uuid=ihost.uuid,
                                    iftype=constants.INTERFACE_TYPE_VLAN, uses=['pxeboot0'],
                                    ifclass=constants.INTERFACE_CLASS_PLATFORM,
                                    vlan_id=mgmt_vlan_id, imac=test_mgmt_mac)
        return ifaces, ports

    def _check_test_interfaces(self, ifaces, ports, inic_dict_array):
        self.assertEqual(self.dbapi.iinterface_get(ifaces['sriov0'].id).imac,
                         inic_dict_array[0]['mac'])
        self.assertEqual(self.dbapi.iinterface_get(ifaces['sriov0a'].id).imac,
                         inic_dict_array[0]['mac'])
        self.assertEqual(self.dbapi.iinterface_get(ifaces['data0'].id).imac,
                         inic_dict_array[1]['mac'])
        self.assertEqual(self.dbapi.iinterface_get(ifaces['pcipt0'].id).imac,
                         inic_dict_array[2]['mac'])
        self.assertEqual(self.dbapi.iinterface_get(ifaces['pxeboot0'].id).imac,
                         inic_dict_array[3]['mac'])
        self.assertEqual(self.dbapi.iinterface_get(ifaces['mgmt0'].id).imac,
                         inic_dict_array[3]['mac'])

        self.assertEqual(self.dbapi.ethernet_port_get(ports['sriov0'].id).mac,
                         inic_dict_array[0]['mac'])
        self.assertEqual(self.dbapi.ethernet_port_get(ports['data0'].id).mac,
                         inic_dict_array[1]['mac'])
        self.assertEqual(self.dbapi.ethernet_port_get(ports['pcipt0'].id).mac,
                         inic_dict_array[2]['mac'])
        self.assertEqual(self.dbapi.ethernet_port_get(ports['pxeboot0'].id).mac,
                         inic_dict_array[3]['mac'])

    def test_iport_update_by_ihost_report_update_same_device_same_slot_diff_mac_sx(self):
        self._iport_update_by_ihost_report_update_same_device_same_slot_diff_mac(True)

    def test_iport_update_by_ihost_report_update_same_device_same_slot_diff_mac_dx(self):
        self._iport_update_by_ihost_report_update_same_device_same_slot_diff_mac(False)

    def _iport_update_by_ihost_report_update_same_device_same_slot_diff_mac(self, is_simplex):
        """Test the interface MAC update

        In case of NIC exchange by the same vendor/device-id the new MAC needs to be updated
        on the database if the system is AIO-SX or AIO-DX.
        For AIO-SX the MAC change is tested on controller-0 and for AIO-DX on controller-1.
        """
        inic_dict_array = self._create_test_iports()
        test_mgmt_mac = inic_dict_array[3]['mac']
        c0_mac = ''
        c1_mac = ''
        if is_simplex:
            c0_mac = test_mgmt_mac
        else:
            c0_mac = '00:15:17:cd:c4:af'
            c1_mac = test_mgmt_mac
        mgmt_vlan_id = 111
        # Create controller-0 node
        config_uuid = str(uuid.uuid4())
        ihost = self._create_test_ihost(
            hostname='controller-0', mgmt_mac=c0_mac, uuid=str(uuid.uuid4()),
            personality=constants.CONTROLLER, config_status=None, config_applied=config_uuid,
            config_target=config_uuid, invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED, operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )
        # For DX, create controller-1 node as well
        if not is_simplex:
            config_uuid = str(uuid.uuid4())
            ihost = self._create_test_ihost(
                hostname='controller-1', mgmt_mac=c1_mac, uuid=str(uuid.uuid4()),
                personality=constants.CONTROLLER, config_status=None, config_applied=config_uuid,
                config_target=config_uuid, invprovision=constants.PROVISIONED,
                administrative=constants.ADMIN_UNLOCKED, operational=constants.OPERATIONAL_ENABLED,
                availability=constants.AVAILABILITY_ONLINE,
            )
        self._create_test_networks(mgmt_vlan_id)

        mock_find_local_mgmt_interface_vlan_id = mock.MagicMock()
        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager._find_local_mgmt_interface_vlan_id',
            mock_find_local_mgmt_interface_vlan_id)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_socket_gethostname = mock.MagicMock()
        p2 = mock.patch('socket.gethostname', mock_socket_gethostname)
        p2.start().return_value = 'controller-0'
        self.addCleanup(p2.stop)

        mock_is_aio_simplex_system = mock.MagicMock()
        p3 = mock.patch('sysinv.common.utils.is_aio_simplex_system', mock_is_aio_simplex_system)
        p3.start().return_value = is_simplex
        self.addCleanup(p3.stop)

        ifaces, ports = self._create_test_interfaces(ihost, inic_dict_array, test_mgmt_mac, mgmt_vlan_id)
        inic_dict_array[0]['mac'] = '1a:2a:3a:4a:5a:6a'
        inic_dict_array[1]['mac'] = 'c0:ca:de:ad:be:ff'
        inic_dict_array[3]['mac'] = '20:2a:2e:2d:2e:2f'

        self.service.iport_update_by_ihost(self.context, ihost['uuid'], inic_dict_array[0:4])
        self._check_test_interfaces(ifaces, ports, inic_dict_array)

    def test_iport_update_by_ihost_report_move_nic_to_other_node(self):
        """Test new NIC on controller-0 and move former NIC from controller-0 to controller-1

        A new NIC is placed on controller-0 and the NIC from controller-0 is moved to controller-1.
        New MAC addresses will be updated on controller-0 and the former MAC addresses from
        controller-0 will be moved to controller-1.
        """
        c0_inic_dict_array = self._create_test_iports()
        c1_inic_dict_array = self._create_test_iports_with_new_macs(1)
        new_c0_inic_dict_array = self._create_test_iports_with_new_macs(2)

        c0_test_mgmt_mac = c0_inic_dict_array[3]['mac']
        c1_test_mgmt_mac = c1_inic_dict_array[3]['mac']
        mgmt_vlan_id = 111
        # Create controller-0 node
        config_uuid0 = str(uuid.uuid4())
        ihost0 = self._create_test_ihost(
            hostname='controller-0', mgmt_mac=c0_test_mgmt_mac, uuid=str(uuid.uuid4()),
            personality=constants.CONTROLLER, config_status=None, config_applied=config_uuid0,
            config_target=config_uuid0, invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED, operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )
        # Create controller-1 node
        config_uuid1 = str(uuid.uuid4())
        ihost1 = self._create_test_ihost(
            hostname='controller-1', mgmt_mac=c1_test_mgmt_mac, uuid=str(uuid.uuid4()),
            personality=constants.CONTROLLER, config_status=None, config_applied=config_uuid1,
            config_target=config_uuid1, invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED, operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )
        self._create_test_networks(mgmt_vlan_id)

        mock_find_local_mgmt_interface_vlan_id = mock.MagicMock()
        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager._find_local_mgmt_interface_vlan_id',
            mock_find_local_mgmt_interface_vlan_id)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_socket_gethostname = mock.MagicMock()
        p2 = mock.patch('socket.gethostname', mock_socket_gethostname)
        p2.start().return_value = 'controller-0'
        self.addCleanup(p2.stop)

        mock_is_aio_simplex_system = mock.MagicMock()
        p3 = mock.patch('sysinv.common.utils.is_aio_simplex_system', mock_is_aio_simplex_system)
        p3.start().return_value = False
        self.addCleanup(p3.stop)

        ifaces0, ports0 = self._create_test_interfaces(ihost0, c0_inic_dict_array, c0_test_mgmt_mac, mgmt_vlan_id)
        ifaces1, ports1 = self._create_test_interfaces(ihost1, c1_inic_dict_array, c1_test_mgmt_mac, mgmt_vlan_id)

        # Update controller-0 with new NIC (new MAC addresses)
        self.service.iport_update_by_ihost(self.context, ihost0['uuid'], new_c0_inic_dict_array[0:4])
        # Update controller-1 with controller-0's original NIC (controller-0's original MAC addresses)
        self.service.iport_update_by_ihost(self.context, ihost1['uuid'], c0_inic_dict_array[0:4])

        # Check new NIC on controller-0
        self._check_test_interfaces(ifaces0, ports0, new_c0_inic_dict_array)
        # Check moved NIC on controller-1
        self._check_test_interfaces(ifaces1, ports1, c0_inic_dict_array)

    def test_iport_update_by_ihost_report_update_different_device_same_slot(self):
        """Test different device exchange on the same PCI address

        In case of NIC exchange with a new vendor/device-id on the same PCI slot, the old entry
        is erased and a new one created if the port associated interface is of class none.
        Otherwise we do not process the new port until the operator removes the existing database.
        We also update the port.node_id if the inode entry related to the numa node is already
        created.
        """
        inic_dict_array = self._create_test_iports()
        test_mgmt_mac = inic_dict_array[3]['mac']
        mgmt_vlan_id = 111
        # Create controller-0 node
        config_uuid = str(uuid.uuid4())
        ihost = self._create_test_ihost(
            hostname='controller-0', mgmt_mac=test_mgmt_mac, uuid=str(uuid.uuid4()),
            personality=constants.CONTROLLER, config_status=None, config_applied=config_uuid,
            config_target=config_uuid, invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED, operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )
        self._create_test_networks(mgmt_vlan_id)

        mock_find_local_mgmt_interface_vlan_id = mock.MagicMock()
        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager._find_local_mgmt_interface_vlan_id',
            mock_find_local_mgmt_interface_vlan_id)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_socket_gethostname = mock.MagicMock()
        p2 = mock.patch('socket.gethostname', mock_socket_gethostname)
        p2.start().return_value = 'controller-0'
        self.addCleanup(p2.stop)

        mock_is_aio_simplex_system = mock.MagicMock()
        p3 = mock.patch('sysinv.common.utils.is_aio_simplex_system', mock_is_aio_simplex_system)
        p3.start().return_value = True
        self.addCleanup(p3.stop)

        port_alarms = dict()

        def port_set_fault(fault):
            port_alarms[fault.entity_instance_id] = fault

        def port_clear_fault(alarm_id, entity_id):
            port_alarms[entity_id].alarm_state = fm_constants.FM_ALARM_STATE_CLEAR

        def port_get_faults_by_id(alarm_id):
            return [fault for fault in port_alarms.values()]

        self.service.fm_api.set_fault.side_effect = port_set_fault
        self.service.fm_api.clear_fault.side_effect = port_clear_fault
        self.service.fm_api.get_faults_by_id.side_effect = port_get_faults_by_id

        ifaces, ports = self._create_test_interfaces(ihost, inic_dict_array, test_mgmt_mac, mgmt_vlan_id)

        # create inodes to update port.node_id
        inuma_dict_array = [{'numa_node': 0, 'capabilities': {}},
                            {'numa_node': 1, 'capabilities': {}}]
        self.service.inumas_update_by_ihost(self.context, ihost['uuid'], inuma_dict_array)

        old_pci_dev = copy.deepcopy(inic_dict_array[0])
        inic_dict_array[0] = inic_dict_array[-1]
        inic_dict_array[0]['pciaddr'] = old_pci_dev['pciaddr']

        self.service.iport_update_by_ihost(self.context, ihost['uuid'], inic_dict_array[0:4])

        # since the port's interface is configured we do not change the DB (the operator needs to
        # do it)
        self.assertEqual(self.dbapi.iinterface_get(ifaces['sriov0'].id).imac,
                         old_pci_dev['mac'])
        self.assertEqual(self.dbapi.iinterface_get(ifaces['sriov0a'].id).imac,
                         old_pci_dev['mac'])
        self.assertEqual(self.dbapi.ethernet_port_get(ports['sriov0'].id).mac,
                         old_pci_dev['mac'])
        self.assertEqual(self.dbapi.ethernet_port_get(ports['sriov0'].id).pvendor,
                         old_pci_dev['pvendor'])
        self.assertEqual(self.dbapi.ethernet_port_get(ports['sriov0'].id).pdevice,
                         old_pci_dev['pdevice'])
        for fault in port_alarms.values():
            self.assertEqual(fault.alarm_state, fm_constants.FM_ALARM_STATE_SET)

        # remove dependant interface
        self.dbapi.iinterface_destroy(ifaces['sriov0a'].id)
        # update interface to class none
        updates = {'ifclass': None}
        self.dbapi.iinterface_update(ifaces['sriov0'].uuid, updates)

        port_db_len = len(self.dbapi.ethernet_port_get_by_host(ihost['uuid']))

        self.service.iport_update_by_ihost(self.context, ihost['uuid'], inic_dict_array[0:4])

        port_found = False
        eth_port_db_list = self.dbapi.ethernet_port_get_by_host(ihost['uuid'])
        for eth_port in eth_port_db_list:
            if (eth_port.pciaddr == inic_dict_array[0]['pciaddr']):
                self.assertEqual(eth_port.mac, inic_dict_array[0]['mac'])
                self.assertEqual(eth_port.pvendor, inic_dict_array[0]['pvendor'])
                self.assertEqual(eth_port.pdevice, inic_dict_array[0]['pdevice'])

                # check if node_id points to the correct inode entry (in our case is 2)
                self.assertEqual(eth_port.node_id, 2)

                iface = self.dbapi.iinterface_get(eth_port.interface_id)
                self.assertEqual(iface.imac, inic_dict_array[0]['mac'])
                self.assertEqual(iface.ifclass, None)
                port_found = True
        self.assertTrue(port_found)
        self.assertEqual(len(self.dbapi.ethernet_port_get_by_host(ihost['uuid'])), port_db_len)
        for fault in port_alarms.values():
            self.assertEqual(fault.alarm_state, fm_constants.FM_ALARM_STATE_CLEAR)

    def test_iport_update_by_ihost_report_with_DB_containing_unreported_device(self):
        """Test when the OS stops reporting a interface

        If the operational system no longer reports a interface this should generate an alarm to
        raise awareness that the DB and the OS are not matching
        The only exception is the data interface because they can be in use by a user space poll
        mode driver like ovs-dpdk, in this case the interface will no longer be available on the
        host OS
        """
        inic_dict_array = self._create_test_iports()
        test_mgmt_mac = inic_dict_array[3]['mac']
        mgmt_vlan_id = 111
        # Create controller-0 node
        config_uuid = str(uuid.uuid4())
        ihost = self._create_test_ihost(
            hostname='controller-0', mgmt_mac=test_mgmt_mac, uuid=str(uuid.uuid4()),
            personality=constants.CONTROLLER, config_status=None, config_applied=config_uuid,
            config_target=config_uuid, invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED, operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )
        self._create_test_networks(mgmt_vlan_id)

        mock_find_local_mgmt_interface_vlan_id = mock.MagicMock()
        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager._find_local_mgmt_interface_vlan_id',
            mock_find_local_mgmt_interface_vlan_id)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_socket_gethostname = mock.MagicMock()
        p2 = mock.patch('socket.gethostname', mock_socket_gethostname)
        p2.start().return_value = 'controller-0'
        self.addCleanup(p2.stop)

        mock_is_aio_simplex_system = mock.MagicMock()
        p3 = mock.patch('sysinv.common.utils.is_aio_simplex_system', mock_is_aio_simplex_system)
        p3.start().return_value = True
        self.addCleanup(p3.stop)

        port_alarms = dict()

        def port_set_fault(fault):
            port_alarms[fault.entity_instance_id] = fault

        def port_clear_fault(alarm_id, entity_id):
            port_alarms[entity_id].alarm_state = fm_constants.FM_ALARM_STATE_CLEAR

        def port_get_faults_by_id(alarm_id):
            return [fault for fault in port_alarms.values()]

        self.service.fm_api.set_fault.side_effect = port_set_fault
        self.service.fm_api.clear_fault.side_effect = port_clear_fault
        self.service.fm_api.get_faults_by_id.side_effect = port_get_faults_by_id

        ifaces, ports = self._create_test_interfaces(ihost, inic_dict_array, test_mgmt_mac, mgmt_vlan_id)

        # create inodes to update port.node_id
        inuma_dict_array = [{'numa_node': 0, 'capabilities': {}},
                            {'numa_node': 1, 'capabilities': {}}]
        self.service.inumas_update_by_ihost(self.context, ihost['uuid'], inuma_dict_array)

        # stop reporting the data interface, it should not generate alarm
        del inic_dict_array[1]

        self.service.iport_update_by_ihost(self.context, ihost['uuid'], inic_dict_array[0:4])
        for fault in port_alarms.values():
            self.assertEqual(fault.alarm_state, fm_constants.FM_ALARM_STATE_CLEAR)

        # stop reporting the sr-iov interface, it should generate alarm
        del inic_dict_array[0]

        self.service.iport_update_by_ihost(self.context, ihost['uuid'], inic_dict_array[0:4])
        for fault in port_alarms.values():
            self.assertEqual(fault.alarm_state, fm_constants.FM_ALARM_STATE_SET)

    def test_iport_update_by_ihost_report_update_same_device_different_slot(self):
        """Test same device exchange on a different PCI address

        In case of NIC exchange with a new vendor/device-id on a different PCI slot, the old entry
        is erased and a new one created if the port associated interface is of class none.
        Otherwise we do not process the new port until the operator removes the existing database.
        We also update the port.node_id if the inode entry related to the numa node is already
        created.
        """
        # Create compute-0 node
        config_uuid = str(uuid.uuid4())
        ihost = self._create_test_ihost(
            hostname='compute-0', mgmt_mac='22:44:33:55:11:77', uuid=str(uuid.uuid4()),
            personality=constants.WORKER, config_status=None, config_applied=config_uuid,
            config_target=config_uuid, invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED, operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        mock_find_local_mgmt_interface_vlan_id = mock.MagicMock()
        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager._find_local_mgmt_interface_vlan_id',
            mock_find_local_mgmt_interface_vlan_id)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_socket_gethostname = mock.MagicMock()
        p2 = mock.patch('socket.gethostname', mock_socket_gethostname)
        p2.start().return_value = 'controller-0'
        self.addCleanup(p2.stop)

        mock_is_aio_simplex_system = mock.MagicMock()
        p3 = mock.patch('sysinv.common.utils.is_aio_simplex_system', mock_is_aio_simplex_system)
        p3.start().return_value = True
        self.addCleanup(p3.stop)

        inic_dict_array = self._create_test_iports()

        # execute initial report
        self.service.iport_update_by_ihost(self.context, ihost['uuid'], inic_dict_array)

        # create inodes
        inuma_dict_array = [{'numa_node': 0, 'capabilities': {}},
                            {'numa_node': 1, 'capabilities': {}}]
        self.service.inumas_update_by_ihost(self.context, ihost['uuid'], inuma_dict_array)

        port_db_len = len(self.dbapi.ethernet_port_get_by_host(ihost['uuid']))

        # now send a report moving the interface to another PCI address
        inic_dict_array2 = self._create_test_iports()
        inic_dict_array2[3]['pciaddr'] = '0000:d3:00.1'
        self.service.iport_update_by_ihost(self.context, ihost['uuid'], inic_dict_array2)

        port_found = False
        eth_port_db_list = self.dbapi.ethernet_port_get_by_host(ihost['uuid'])
        for eth_port in eth_port_db_list:
            if (eth_port.pciaddr == inic_dict_array2[3]['pciaddr']):
                self.assertEqual(eth_port.mac, inic_dict_array2[3]['mac'])
                self.assertEqual(eth_port.pvendor, inic_dict_array2[3]['pvendor'])
                self.assertEqual(eth_port.pdevice, inic_dict_array2[3]['pdevice'])

                # check if node_id points to the correct inode entry (in our case is 2)
                self.assertEqual(eth_port.node_id, 2)

                iface = self.dbapi.iinterface_get(eth_port.interface_id)
                self.assertEqual(iface.imac, inic_dict_array2[3]['mac'])
                self.assertEqual(iface.ifclass, None)
                port_found = True
        self.assertTrue(port_found)
        self.assertEqual(len(self.dbapi.ethernet_port_get_by_host(ihost['uuid'])), port_db_len)

    def test_iport_update_by_ihost_report_update_after_n3000_reset_sx(self):
        self._iport_update_by_ihost_report_update_after_n3000_reset(True)

    def test_iport_update_by_ihost_report_update_after_n3000_reset_dx(self):
        self._iport_update_by_ihost_report_update_after_n3000_reset(False)

    def _iport_update_by_ihost_report_update_after_n3000_reset(self, is_simplex):
        """Test same device exchange on a different PCI address

        In case of a N3000 reset, the PCI address of the onboard devices can be changed.
        This test case makes sure that the PCI address in the database is updated correctly
        for the 0d58 devices.
        """
        # Create controller-0 node
        config_uuid = str(uuid.uuid4())
        ihost = self._create_test_ihost(
            hostname='controller-0', mgmt_mac='22:44:33:55:11:77', uuid=str(uuid.uuid4()),
            personality=constants.CONTROLLER, config_status=None, config_applied=config_uuid,
            config_target=config_uuid, invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED, operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        mock_find_local_mgmt_interface_vlan_id = mock.MagicMock()
        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager._find_local_mgmt_interface_vlan_id',
            mock_find_local_mgmt_interface_vlan_id)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_socket_gethostname = mock.MagicMock()
        p2 = mock.patch('socket.gethostname', mock_socket_gethostname)
        p2.start().return_value = 'controller-0'
        self.addCleanup(p2.stop)

        mock_is_aio_simplex_system = mock.MagicMock()
        p3 = mock.patch('sysinv.common.utils.is_aio_simplex_system', mock_is_aio_simplex_system)
        p3.start().return_value = is_simplex
        self.addCleanup(p3.stop)

        inic_dict_array = self._create_test_iports()

        # execute initial report
        self.service.iport_update_by_ihost(self.context, ihost['uuid'], inic_dict_array)

        # create inodes
        inuma_dict_array = [{'numa_node': 0, 'capabilities': {}},
                            {'numa_node': 1, 'capabilities': {}}]
        self.service.inumas_update_by_ihost(self.context, ihost['uuid'], inuma_dict_array)

        port_db_len = len(self.dbapi.ethernet_port_get_by_host(ihost['uuid']))

        # now send a report changing one 0d58 device to another PCI address and remove
        # one N3000 port
        inic_dict_array2 = self._create_test_iports()
        inic_dict_array2[6]['pciaddr'] = '0000:b2:00.1'
        inic_dict_array2[6]['pdevice'] = 'Ethernet Controller X710 for 10GbE SFP+ [1572]'
        mac_to_remove = inic_dict_array2[7]['mac']
        inic_dict_array2.pop(7)

        for it_port in inic_dict_array2:
            port = self.dbapi.ethernet_port_get_by_mac(it_port['mac'])
            it_port['interface_uuid'] = port['interface_uuid']

        self.service.iport_update_by_ihost(self.context, ihost['uuid'], inic_dict_array2)

        port_found = False
        eth_port_db_list = self.dbapi.ethernet_port_get_by_host(ihost['uuid'])
        for eth_port in eth_port_db_list:
            if (eth_port.pciaddr == inic_dict_array2[6]['pciaddr']):
                self.assertEqual(eth_port.mac, inic_dict_array2[6]['mac'])
                self.assertEqual(eth_port.pvendor, inic_dict_array2[6]['pvendor'])
                self.assertNotEqual(eth_port.pdevice, inic_dict_array2[6]['pdevice'])
                self.assertEqual(eth_port.interface_uuid, inic_dict_array2[6]['interface_uuid'])

                # check if node_id points to the correct inode entry (in our case is 2)
                self.assertEqual(eth_port.node_id, 2)

                iface = self.dbapi.iinterface_get(eth_port.interface_id)
                self.assertEqual(iface.imac, inic_dict_array2[6]['mac'])
                self.assertEqual(iface.ifclass, None)
                port_found = True
        self.assertTrue(port_found)
        self.assertEqual(len(self.dbapi.ethernet_port_get_by_host(ihost['uuid'])) + 1, port_db_len)

        # guarantee that any unreported entry with a specific MAC address is deleted.
        mac_found = False
        if any(mac_to_remove == eth_port.mac for eth_port in eth_port_db_list):
            mac_found = True
        self.assertFalse(mac_found)

    def test_iport_update_by_ihost_report_with_changed_device_and_vendor_description(self):
        """Test when the OS reports a new vendor or device description, but the ID is unchanged

        During upgrade the new version might change the device/vendor description due to a new
        driver version, but the ID never changes. This test implements an update that only contains
        change on the descriptio part of vendor and device (ID remains unchanged)
        """
        inic_dict_array = self._create_test_iports()
        test_mgmt_mac = inic_dict_array[3]['mac']
        mgmt_vlan_id = 111
        # Create controller-0 node
        config_uuid = str(uuid.uuid4())
        ihost = self._create_test_ihost(
            hostname='controller-0', mgmt_mac=test_mgmt_mac, uuid=str(uuid.uuid4()),
            personality=constants.WORKER, config_status=None, config_applied=config_uuid,
            config_target=config_uuid, invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED, operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )
        self._create_test_networks(mgmt_vlan_id)

        mock_find_local_mgmt_interface_vlan_id = mock.MagicMock()
        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager._find_local_mgmt_interface_vlan_id',
            mock_find_local_mgmt_interface_vlan_id)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_socket_gethostname = mock.MagicMock()
        p2 = mock.patch('socket.gethostname', mock_socket_gethostname)
        p2.start().return_value = 'controller-0'
        self.addCleanup(p2.stop)

        mock_is_aio_simplex_system = mock.MagicMock()
        p3 = mock.patch('sysinv.common.utils.is_aio_simplex_system', mock_is_aio_simplex_system)
        p3.start().return_value = True
        self.addCleanup(p3.stop)

        port_alarms = dict()

        def port_set_fault(fault):
            port_alarms[fault.entity_instance_id] = fault

        def port_clear_fault(alarm_id, entity_id):
            port_alarms[entity_id].alarm_state = fm_constants.FM_ALARM_STATE_CLEAR

        def port_get_faults_by_id(alarm_id):
            return [fault for fault in port_alarms.values()]

        self.service.fm_api.set_fault.side_effect = port_set_fault
        self.service.fm_api.clear_fault.side_effect = port_clear_fault
        self.service.fm_api.get_faults_by_id.side_effect = port_get_faults_by_id

        ifaces, ports = self._create_test_interfaces(ihost, inic_dict_array, test_mgmt_mac, mgmt_vlan_id)

        # create inodes to update port.node_id
        inuma_dict_array = [{'numa_node': 0, 'capabilities': {}},
                            {'numa_node': 1, 'capabilities': {}}]
        self.service.inumas_update_by_ihost(self.context, ihost['uuid'], inuma_dict_array)

        # Change only the description on the device/vendor field
        inic_dict_array[1]['pvendor'] = 'Good Old Intel Corporation [8086]'
        inic_dict_array[1]['pdevice'] = 'Device [1572]'
        inic_dict_array[2]['pdevice'] = 'Device [105e]'
        inic_dict_array[3]['pvendor'] = 'Good old Intel Corporation [8086]'

        self.service.iport_update_by_ihost(self.context, ihost['uuid'], inic_dict_array)

        self.assertEqual(len(port_alarms), 0)

        eth_port_db_list = self.dbapi.ethernet_port_get_by_host(ihost['uuid'])
        found = False
        for inic in inic_dict_array:
            for eth_port in eth_port_db_list:
                if (eth_port.pciaddr == inic['pciaddr']):
                    self.assertEqual(eth_port.mac, inic['mac'])
                    self.assertEqual(eth_port.pvendor, inic['pvendor'])
                    self.assertEqual(eth_port.pdevice, inic['pdevice'])
                    self.assertEqual(eth_port.name, inic['pname'])
                    self.assertEqual(eth_port.driver, inic['driver'])
                    found = True
        self.assertTrue(found)

    def _create_test_pci_device_report(self, use_acc100=False):
        dev1 = {'sriov_vf_driver': None, 'numa_node': 0, 'name': 'pci_0000_00_11_0',
            'sriov_numvfs': 0, 'driver': None, 'pclass_id': 'ff0000',
            'pclass': 'Unassigned class [ff00]', 'pdevice_id': 'a1ec',
            'psdevice': 'Device 0000', 'fpga_n3000_reset': True, 'sriov_vf_pdevice_id': None,
            'sriov_totalvfs': None, 'pciaddr': '0000:00:11.0',
            'pdevice': 'C620 Series Chipset Family MROM 0', 'pvendor_id': '8086',
            'sriov_vfs_pci_address': '', 'extra_info': None,
            'psvendor': 'Intel Corporation', 'enabled': False, 'pvendor': 'Intel Corporation'}
        dev2 = {'sriov_vf_driver': None, 'numa_node': 0, 'name': 'pci_0000_00_11_5',
            'sriov_numvfs': 0, 'driver': 'ahci', 'pclass_id': '010601',
            'pclass': 'SATA controller', 'pdevice_id': 'a1d2',
            'psdevice': 'Intel Corporation', 'fpga_n3000_reset': True,
            'sriov_vf_pdevice_id': None, 'sriov_totalvfs': None, 'pciaddr': '0000:00:11.5',
            'pdevice': 'C620 Series Chipset Family SSATA Controller [AHCI mode]',
            'pvendor_id': '8086', 'sriov_vfs_pci_address': '', 'extra_info': None,
            'psvendor': '-p01', 'enabled': False,
            'pvendor': 'Intel Corporation'}
        dev3 = {'sriov_vf_driver': None, 'numa_node': 0, 'name': 'pci_0000_00_14_0',
            'sriov_numvfs': 0, 'driver': None, 'pclass_id': '0c0330',
            'pclass': 'USB controller', 'pdevice_id': 'a1af', 'psdevice': 'Intel Corporation',
            'fpga_n3000_reset': True, 'sriov_vf_pdevice_id': None, 'sriov_totalvfs': None,
            'pciaddr': '0000:00:14.0', 'pdevice': 'C620 Series Family USB 3.0 xHCI Controller',
            'pvendor_id': '8086', 'sriov_vfs_pci_address': '', 'extra_info': None,
            'psvendor': '-p30', 'enabled': False,
            'pvendor': 'Intel Corporation'}
        dev4 = {'sriov_vf_driver': None, 'numa_node': 0, 'name': 'pci_0000_00_14_2',
            'sriov_numvfs': 0, 'driver': None, 'pclass_id': '118000',
            'pclass': 'Signal processing controller', 'pdevice_id': 'a1b1',
            'psdevice': 'Device 35cf', 'fpga_n3000_reset': True, 'sriov_vf_pdevice_id': None,
            'sriov_totalvfs': None, 'pciaddr': '0000:00:14.2',
            'pdevice': 'C620 Series Chipset Family Thermal Subsystem', 'pvendor_id': '8086',
            'sriov_vfs_pci_address': '', 'extra_info': None,
            'psvendor': 'Intel Corporation', 'enabled': False, 'pvendor': 'Intel Corporation'}
        dev5 = {'sriov_vf_driver': None, 'numa_node': 0, 'name': 'pci_0000_00_16_4',
            'sriov_numvfs': 0, 'driver': None, 'pclass_id': '078000',
            'pclass': 'Communication controller', 'pdevice_id': 'a1be',
            'psdevice': 'Device 35cf', 'fpga_n3000_reset': True, 'sriov_vf_pdevice_id': None,
            'sriov_totalvfs': None, 'pciaddr': '0000:00:16.4',
            'pdevice': 'C620 Series Chipset Family MEI Controller #3', 'pvendor_id': '8086',
            'sriov_vfs_pci_address': '', 'extra_info': None,
            'psvendor': 'Intel Corporation', 'enabled': False, 'pvendor': 'Intel Corporation'}
        dev6 = {'sriov_vf_driver': None, 'numa_node': 0, 'name': 'pci_0000_00_1f_4',
            'sriov_numvfs': 0, 'driver': 'i801_smbus', 'pclass_id': '0c0500', 'pclass': 'SMBus',
            'pdevice_id': 'a1a3', 'psdevice': 'Device 35cf', 'fpga_n3000_reset': True,
            'sriov_vf_pdevice_id': None, 'sriov_totalvfs': None, 'pciaddr': '0000:00:1f.4',
            'pdevice': 'C620 Series Chipset Family SMBus', 'pvendor_id': '8086',
            'sriov_vfs_pci_address': '', 'extra_info': None,
            'psvendor': 'Intel Corporation', 'enabled': False, 'pvendor': 'Intel Corporation'}
        dev7 = {'sriov_vf_driver': None, 'numa_node': 0, 'name': 'pci_0000_00_1f_5',
            'sriov_numvfs': 0, 'driver': None, 'pclass_id': '0c8000',
            'pclass': 'Serial bus controller [0c80]', 'pdevice_id': 'a1a4',
            'psdevice': 'Device 35cf', 'fpga_n3000_reset': True, 'sriov_vf_pdevice_id': None,
            'sriov_totalvfs': None, 'pciaddr': '0000:00:1f.5',
            'pdevice': 'C620 Series Chipset Family SPI Controller', 'pvendor_id': '8086',
            'sriov_vfs_pci_address': '', 'extra_info': None,
            'psvendor': 'Intel Corporation', 'enabled': False, 'pvendor': 'Intel Corporation'}
        dev8 = {'sriov_vf_driver': None, 'numa_node': 0, 'name': 'pci_0000_02_00_0',
            'sriov_numvfs': 0, 'driver': None, 'pclass_id': '030000',
            'pclass': 'VGA compatible controller', 'pdevice_id': '2000',
            'psdevice': 'ASPEED Graphics Family', 'fpga_n3000_reset': True,
            'sriov_vf_pdevice_id': None, 'sriov_totalvfs': None, 'pciaddr': '0000:02:00.0',
            'pdevice': 'ASPEED Graphics Family', 'pvendor_id': '1a03', 'sriov_vfs_pci_address': '',
            'extra_info': None, 'psvendor': 'ASPEED Technology, Inc.',
            'enabled': True, 'pvendor': 'ASPEED Technology, Inc.'}
        dev9 = {'sriov_vf_driver': None, 'numa_node': 0, 'name': 'pci_0000_18_00_0',
            'sriov_numvfs': 0, 'driver': 'megaraid_sas', 'pclass_id': '010400',
            'pclass': 'RAID bus controller', 'pdevice_id': '0017',
            'psdevice': 'RAID Controller RSP3WD080E', 'fpga_n3000_reset': True,
            'sriov_vf_pdevice_id': None, 'sriov_totalvfs': None, 'pciaddr': '0000:18:00.0',
            'pdevice': 'MegaRAID Tri-Mode SAS3408', 'pvendor_id': '1000',
            'sriov_vfs_pci_address': '', 'extra_info': None,
            'psvendor': 'Intel Corporation', 'enabled': False,
            'pvendor': 'LSI Logic / Symbios Logic'}
        dev10 = {'sriov_vf_driver': 'c6xxvf', 'numa_node': 0, 'name': 'pci_0000_3d_00_0',
            'sriov_numvfs': 3, 'driver': 'c6xx', 'pclass_id': '0b4000',
            'pclass': 'Co-processor', 'pdevice_id': '37c8', 'psdevice': 'Device 35cf',
            'fpga_n3000_reset': True, 'sriov_vf_pdevice_id': '37c9', 'sriov_totalvfs': 16,
            'pciaddr': '0000:3d:00.0', 'pdevice': 'C62x Chipset QuickAssist Technology',
            'pvendor_id': '8086', 'sriov_vfs_pci_address': '0000:3d:01.0,0000:3d:01.1,0000:3d:01.2',
            'extra_info': None, 'psvendor': 'Intel Corporation',
            'enabled': True, 'pvendor': 'Intel Corporation'}
        n3000_fpga = {'name': 'pci_0000_b2_00_0', 'pciaddr': '0000:b2:00.0', 'pclass_id': '120000',
            'pvendor_id': '8086', 'pdevice_id': '0b30', 'pclass': 'Processing accelerators',
            'pvendor': 'Intel Corporation', 'pdevice': 'Device 0b30',
            'psvendor': 'Intel Corporation', 'psdevice': 'Device 0000', 'numa_node': 1,
            'driver': 'intel-fpga-pci', 'sriov_totalvfs': 1, 'sriov_numvfs': 0,
            'sriov_vfs_pci_address': '', 'enabled': True, 'extra_info': None,
            'sriov_vf_driver': None, 'sriov_vf_pdevice_id': None, 'fpga_n3000_reset': True}
        n3000_pf = {'name': 'pci_0000_b4_00_0', 'pciaddr': '0000:b4:00.0', 'pclass_id': '120000',
            'pvendor_id': '8086', 'pdevice_id': '0d8f', 'pclass': 'Processing accelerators',
            'pvendor': 'Intel Corporation', 'pdevice': 'Device 0d8f',
            'psvendor': 'Intel Corporation', 'psdevice': 'Device 0001', 'numa_node': 1,
            'driver': 'igb_uio', 'sriov_totalvfs': 8, 'sriov_numvfs': 4,
            'sriov_vfs_pci_address': '0000:b4:00.1,0000:b4:00.2,0000:b4:00.3,0000:b4:00.4',
            'enabled': True, 'extra_info': None, 'sriov_vf_driver': 'vfio-pci',
            'sriov_vf_pdevice_id': '0d90', 'fpga_n3000_reset': True}
        acc100 = {'name': 'pci_0000_b4_00_0', 'pciaddr': '0000:b4:00.0', 'pclass_id': '120001',
            'pvendor_id': '8086', 'pdevice_id': '0d5c', 'pclass': 'Processing accelerators',
            'pvendor': 'Intel Corporation', 'pdevice': 'Device 0d5c',
            'psvendor': 'Intel Corporation', 'psdevice': 'Device 0000', 'numa_node': 0,
            'driver': 'igb_uio', 'sriov_totalvfs': 16, 'sriov_numvfs': 4,
            'sriov_vfs_pci_address': '0000:b4:00.1,0000:b4:00.2,0000:b4:00.3,0000:b4:00.4',
            'enabled': True, 'extra_info': None, 'sriov_vf_driver': 'vfio',
            'sriov_vf_pdevice_id': '0d5d', 'fpga_n3000_reset': False}

        response = [dev1, dev2, dev3, dev4, dev5, dev6, dev7, dev8, dev9, dev10]
        if not use_acc100:
            response.append(n3000_fpga)
            response.append(n3000_pf)
        else:
            response.append(acc100)
            for dev in response:
                dev['fpga_n3000_reset'] = False

        return response

    def test_pci_device_update_by_host(self):
        # Create compute-0 node
        config_uuid = str(uuid.uuid4())
        ihost = self._create_test_ihost(
            personality=constants.WORKER,
            hostname='compute-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        host_uuid = ihost['uuid']
        host_id = ihost['id']
        PCI_DEV_1 = {'uuid': str(uuid.uuid4()),
                     'name': 'pci_dev_1',
                     'pciaddr': '0000:0b:01.0',
                     'pclass_id': '060100',
                     'pvendor_id': '8086',
                     'pdevice_id': '0443',
                     'enabled': True}
        PCI_DEV_2 = {'uuid': str(uuid.uuid4()),
                     'name': 'pci_dev_2',
                     'pciaddr': '0000:0c:01.0',
                     'pclass_id': '060200',
                     'pvendor_id': '8088',
                     'pdevice_id': '0444',
                     'enabled': True}
        pci_device_dict_array = [PCI_DEV_1, PCI_DEV_2]

        # create new dev
        self.service.pci_device_update_by_host(self.context, host_uuid, pci_device_dict_array)

        dev = self.dbapi.pci_device_get(PCI_DEV_1['pciaddr'], host_id)
        for key in PCI_DEV_1:
            self.assertEqual(dev[key], PCI_DEV_1[key])

        dev = self.dbapi.pci_device_get(PCI_DEV_2['pciaddr'], host_id)
        for key in PCI_DEV_2:
            self.assertEqual(dev[key], PCI_DEV_2[key])

        # update existed dev
        pci_dev_dict_update1 = [{'pciaddr': PCI_DEV_2['pciaddr'],
                                'pclass_id': '060500',
                                'pvendor_id': '8086',
                                'pdevice_id': '0449',
                                'pclass': '0600',
                                'pvendor': '',
                                'psvendor': '',
                                'psdevice': 'qat',
                                'sriov_totalvfs': 32,
                                'sriov_numvfs': 4,
                                'sriov_vf_driver': None,
                                'sriov_vf_pdevice_id': '0450',
                                'sriov_vfs_pci_address': '',
                                'driver': ''}]
        self.service.pci_device_update_by_host(self.context, host_uuid, pci_dev_dict_update1)

        dev = self.dbapi.pci_device_get(PCI_DEV_2['pciaddr'], host_id)

        for key in pci_dev_dict_update1[0]:
            self.assertEqual(dev[key], pci_dev_dict_update1[0][key])

        # update existed dev failure case, failed to change uuid.
        pci_dev_dict_update2 = [{'pciaddr': PCI_DEV_2['pciaddr'],
                                'pclass_id': '060500',
                                'pvendor_id': '8086',
                                'pdevice_id': '0449',
                                'pclass': '0600',
                                'pvendor': '',
                                'psvendor': '',
                                'psdevice': 'qat',
                                'sriov_totalvfs': 32,
                                'sriov_numvfs': 4,
                                'sriov_vf_driver': None,
                                'sriov_vf_pdevice_id': '0450',
                                'sriov_vfs_pci_address': '',
                                'driver': '',
                                'uuid': 1122}]

        self.service.pci_device_update_by_host(self.context, host_uuid, pci_dev_dict_update2)
        dev = self.dbapi.pci_device_get(PCI_DEV_2['pciaddr'], host_id)
        self.assertEqual(dev['uuid'], PCI_DEV_2['uuid'])

    def test_pci_device_update_n3000_by_host(self):
        # Create compute-0 node
        config_uuid = str(uuid.uuid4())
        ihost = self._create_test_ihost(
            personality=constants.WORKER,
            hostname='compute-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )
        host_uuid = ihost['uuid']
        host_id = ihost['id']
        PCI_DEV_1 = {'uuid': str(uuid.uuid4()),
                     'name': 'pci_dev_1',
                     'pciaddr': '0000:0b:01.0',
                     'pclass_id': '060100',
                     'pvendor_id': '8086',
                     'pdevice_id': '0443',
                     'enabled': True,
                     'fpga_n3000_reset': True}  # is the FPGA reset
        PCI_DEV_2 = {'uuid': str(uuid.uuid4()),
                     'name': 'pci_0000_b4_00_0',
                     'pciaddr': '0000:b4:00.0',
                     'pclass_id': '120000',
                     'pvendor_id': '8086',
                     'pdevice_id': '0d8f',  # N3000 FEC
                     'enabled': True,
                     'fpga_n3000_reset': True}  # is the FPGA reset

        pci_device_dict_array = [PCI_DEV_1, PCI_DEV_2]

        # create new dev
        self.service.pci_device_update_by_host(self.context, host_uuid, pci_device_dict_array)

        dev = self.dbapi.pci_device_get(PCI_DEV_1['pciaddr'], host_id)
        for key in PCI_DEV_1:
            self.assertEqual(dev[key], PCI_DEV_1[key])

        dev = self.dbapi.pci_device_get(PCI_DEV_2['pciaddr'], host_id)
        for key in PCI_DEV_2:
            self.assertEqual(dev[key], PCI_DEV_2[key])

        # test with fpga_n3000_reset as False
        PCI_DEV_3 = {'uuid': str(uuid.uuid4()),
                     'name': 'pci_dev_3',
                     'pciaddr': '0000:0c:01.0',
                     'pclass_id': '060100',
                     'pvendor_id': '8086',
                     'pdevice_id': '0443',
                     'enabled': True,
                     'fpga_n3000_reset': False}  # is the FPGA reset
        PCI_DEV_4 = {'uuid': str(uuid.uuid4()),
                     'name': 'pci_0000_b8_00_0',
                     'pciaddr': '0000:b8:00.0',
                     'pclass_id': '120000',
                     'pvendor_id': '8086',
                     'pdevice_id': '0d8f',  # N3000_FEC_PF_DEVICE
                     'enabled': True,
                     'fpga_n3000_reset': False}  # is the FPGA reset
        PCI_DEV_5 = {'uuid': str(uuid.uuid4()),
                     'name': 'pci_0000_b9_00_0',
                     'pciaddr': '0000:b9:00.0',
                     'pclass_id': '120000',
                     'pvendor_id': '8086',
                     'pdevice_id': '0b30',  # N3000_DEVICE
                     'enabled': True,
                     'fpga_n3000_reset': False}  # is the FPGA reset
        PCI_DEV_6 = {'uuid': str(uuid.uuid4()),
                     'name': 'pci_0000_b0_00_0',
                     'pciaddr': '0000:b0:00.0',
                     'pclass_id': '120000',
                     'pvendor_id': '8086',
                     'pdevice_id': '0b32',  # N3000_DEFAULT_DEVICE
                     'enabled': True,
                     'fpga_n3000_reset': False}  # is the FPGA reset

        pci_device_dict_array2 = [PCI_DEV_3, PCI_DEV_4, PCI_DEV_5, PCI_DEV_6]

        self.service.pci_device_update_by_host(self.context, host_uuid, pci_device_dict_array2)

        dev = self.dbapi.pci_device_get(PCI_DEV_3['pciaddr'], host_id)
        for key in PCI_DEV_3:
            self.assertEqual(dev[key], PCI_DEV_3[key])

        self.assertRaises(exception.ServerNotFound,
                          self.dbapi.pci_device_get, PCI_DEV_4['pciaddr'], host_id)
        self.assertRaises(exception.ServerNotFound,
                          self.dbapi.pci_device_get, PCI_DEV_5['pciaddr'], host_id)
        self.assertRaises(exception.ServerNotFound,
                          self.dbapi.pci_device_get, PCI_DEV_6['pciaddr'], host_id)

        # update existing dev
        pci_dev_dict_update = [{'pciaddr': PCI_DEV_2['pciaddr'],
                                'name': PCI_DEV_2['name'],
                                'pclass_id': '060500',
                                'pvendor_id': '8086',
                                'pdevice_id': '0d8f',
                                'pclass': '0600',
                                'pvendor': '',
                                'psvendor': '',
                                'psdevice': 'qat',
                                'sriov_totalvfs': 32,
                                'sriov_numvfs': 4,
                                'sriov_vf_driver': 'vfio-pci',
                                'sriov_vf_pdevice_id': '0d90',
                                'sriov_vfs_pci_address': '000:b4:00.1,0000:b4:00.2,0000:b4:00.3',
                                'driver': 'igb_uio',
                                'fpga_n3000_reset': True}]
        self.service.pci_device_update_by_host(self.context, host_uuid, pci_dev_dict_update)
        dev = self.dbapi.pci_device_get(PCI_DEV_2['pciaddr'], host_id)

        for key in pci_dev_dict_update[0]:
            self.assertEqual(dev[key], pci_dev_dict_update[0][key])

        pci_dev_dict_update[0]['sriov_vfs_pci_address'] = ''
        pci_dev_dict_update[0]['fpga_n3000_reset'] = False
        self.service.pci_device_update_by_host(self.context, host_uuid, pci_dev_dict_update)
        dev = self.dbapi.pci_device_get(PCI_DEV_2['pciaddr'], host_id)
        self.assertNotEqual(dev['sriov_vfs_pci_address'],
                            pci_dev_dict_update[0]['sriov_vfs_pci_address'])

    def test_pci_device_update_n3000_replacement_different_slot(self):
        """ Test if an update contains a n3000 on a different PCI address

        In AIO-SX it is possible to plug a N3000 card without a new server installation, this
        test check that the pci_device database will take into account the card replacement on a new
        PCI slot, by removing the old entry and creating the new one. On N3000 case the opertaion
        is only executed if the reset operation was successful
        """
        mock_is_aio_simplex_system = mock.MagicMock()
        p3 = mock.patch('sysinv.common.utils.is_aio_simplex_system', mock_is_aio_simplex_system)
        p3.start().return_value = True
        self.addCleanup(p3.stop)

        # Create controller-0 node
        config_uuid = str(uuid.uuid4())
        ihost = self._create_test_ihost(
            hostname='controller-0', mgmt_mac="1a:2a:3a:4a:5a:6a", uuid=str(uuid.uuid4()),
            personality=constants.CONTROLLER, config_status=None, config_applied=config_uuid,
            config_target=config_uuid, invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED, operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        # create new dev with N3000 already reset
        pci_device_report1 = self._create_test_pci_device_report()
        self.service.pci_device_update_by_host(self.context, ihost['uuid'], pci_device_report1)

        for pci_dev in pci_device_report1:
            db_dev = self.dbapi.pci_device_get(pci_dev['pciaddr'], ihost['id'])
            for key in pci_dev:
                self.assertEqual(pci_dev[key], db_dev[key])

        # N3000 moves to a different slot and the first report might be without reset
        pci_device_report2 = self._create_test_pci_device_report()
        old_n3000_fpga = copy.deepcopy(pci_device_report2[-2])
        del old_n3000_fpga['fpga_n3000_reset']  # this field is removed in the conductor
        old_n3000_pf = copy.deepcopy(pci_device_report2[-1])
        del old_n3000_pf['fpga_n3000_reset']  # this field is removed in the conductor
        pci_device_report2[-2]['name'] = 'pci_0000_c3_00_0'
        pci_device_report2[-2]['pciaddr'] = '0000:c3:00.0'
        pci_device_report2[-1]['name'] = 'pci_0000_c7_00_0'
        pci_device_report2[-1]['pciaddr'] = '0000:c7:00.0'
        for pci_dev in pci_device_report2:
            pci_dev['fpga_n3000_reset'] = False

        self.service.pci_device_update_by_host(self.context, ihost['uuid'],
                                               pci_device_report2)

        self.assertRaises(exception.ServerNotFound,
                    self.dbapi.pci_device_get, pci_device_report2[-2]['pciaddr'], ihost['id'])
        self.assertRaises(exception.ServerNotFound,
                     self.dbapi.pci_device_get, pci_device_report2[-1]['pciaddr'], ihost['id'])
        db_dev = self.dbapi.pci_device_get(old_n3000_fpga['pciaddr'], ihost['id'])
        for key in old_n3000_fpga:
            self.assertEqual(old_n3000_fpga[key], db_dev[key])
        db_dev = self.dbapi.pci_device_get(old_n3000_pf['pciaddr'], ihost['id'])
        for key in old_n3000_pf:
            self.assertEqual(old_n3000_pf[key], db_dev[key])

        # N3000 report with reset executed
        pci_device_report3 = self._create_test_pci_device_report()
        pci_device_report3[-2]['name'] = 'pci_0000_c2_00_0'
        pci_device_report3[-2]['pciaddr'] = '0000:c2:00.0'
        pci_device_report3[-1]['name'] = 'pci_0000_c4_00_0'
        pci_device_report3[-1]['pciaddr'] = '0000:c4:00.0'
        for pci_dev in pci_device_report3:
            pci_dev['fpga_n3000_reset'] = True
        self.service.pci_device_update_by_host(self.context, ihost['uuid'],
                                               pci_device_report3)

        self.assertRaises(exception.ServerNotFound,
                    self.dbapi.pci_device_get, old_n3000_fpga['pciaddr'], ihost['id'])
        self.assertRaises(exception.ServerNotFound,
                     self.dbapi.pci_device_get, old_n3000_pf['pciaddr'], ihost['id'])
        db_dev = self.dbapi.pci_device_get(pci_device_report3[-2]['pciaddr'], ihost['id'])
        for key in pci_device_report3[-2]:
            self.assertEqual(pci_device_report3[-2][key], db_dev[key])
        db_dev = self.dbapi.pci_device_get(pci_device_report3[-1]['pciaddr'], ihost['id'])
        for key in pci_device_report3[-1]:
            self.assertEqual(pci_device_report3[-1][key], db_dev[key])

    def test_pci_device_update_acc100_replacement_different_slot(self):
        """ Test if an update contains an ACC100 on a different PCI address

        In AIO-SX it is possible to plug a ACC100 card without a new server installation, this
        test check that the pci_device database will take into account the card replacement on a new
        PCI slot, by removing the old entry and creating the new one.
        """
        mock_is_aio_simplex_system = mock.MagicMock()
        p3 = mock.patch('sysinv.common.utils.is_aio_simplex_system', mock_is_aio_simplex_system)
        p3.start().return_value = True
        self.addCleanup(p3.stop)

        # Create controller-0 node
        config_uuid = str(uuid.uuid4())
        ihost = self._create_test_ihost(
            hostname='controller-0', mgmt_mac="1a:2a:3a:4a:5a:6a", uuid=str(uuid.uuid4()),
            personality=constants.CONTROLLER, config_status=None, config_applied=config_uuid,
            config_target=config_uuid, invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED, operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        # create new devices with ACC100
        pci_device_report1 = self._create_test_pci_device_report(True)
        acc100_addr = pci_device_report1[-1]['pciaddr']
        self.service.pci_device_update_by_host(self.context, ihost['uuid'], pci_device_report1)

        for pci_dev in pci_device_report1:
            db_dev = self.dbapi.pci_device_get(pci_dev['pciaddr'], ihost['id'])
            for key in pci_dev:
                self.assertEqual(pci_dev[key], db_dev[key])

        # ACC100 reports on a different slot
        pci_device_report2 = self._create_test_pci_device_report(True)
        pci_device_report2[-1]['name'] = 'pci_0000_c4_00_0'
        pci_device_report2[-1]['pciaddr'] = '0000:c4:00.0'

        self.service.pci_device_update_by_host(self.context, ihost['uuid'], pci_device_report2)

        self.assertRaises(exception.ServerNotFound,
                    self.dbapi.pci_device_get, acc100_addr, ihost['id'])
        for pci_dev in pci_device_report2:
            db_dev = self.dbapi.pci_device_get(pci_dev['pciaddr'], ihost['id'])
            for key in pci_dev:
                self.assertEqual(pci_dev[key], db_dev[key])

    def test_pci_device_update_acc100_replacement_to_n3000_same_slot(self):
        """ Test if an update contains a FEC card replacement on the same slot

        In AIO-SX it is possible to replace a N3000 to ACC100 (or vice-versa). This test checks if
        the previous FEC card entry are erased if the PCI address of the new card matches the
        old card
        """
        mock_is_aio_simplex_system = mock.MagicMock()
        p3 = mock.patch('sysinv.common.utils.is_aio_simplex_system', mock_is_aio_simplex_system)
        p3.start().return_value = True
        self.addCleanup(p3.stop)

        # Create controller-0 node
        config_uuid = str(uuid.uuid4())
        ihost = self._create_test_ihost(
            hostname='controller-0', mgmt_mac="1a:2a:3a:4a:5a:6a", uuid=str(uuid.uuid4()),
            personality=constants.CONTROLLER, config_status=None, config_applied=config_uuid,
            config_target=config_uuid, invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED, operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        # create new dev with N3000 already reset
        pci_device_report1 = self._create_test_pci_device_report()
        self.service.pci_device_update_by_host(self.context, ihost['uuid'], pci_device_report1)

        # ACC100 reports on the same N3000 slot
        pci_device_report2 = self._create_test_pci_device_report(True)

        self.service.pci_device_update_by_host(self.context, ihost['uuid'], pci_device_report2)

        self.assertRaises(exception.ServerNotFound,
                    self.dbapi.pci_device_get, '0000:b2:00.0', ihost['id'])
        for pci_dev in pci_device_report2:
            db_dev = self.dbapi.pci_device_get(pci_dev['pciaddr'], ihost['id'])
            for key in pci_dev:
                self.assertEqual(pci_dev[key], db_dev[key])

        # N3000 without reset replaces ACC100
        pci_device_report3 = self._create_test_pci_device_report()
        pci_device_report3[-2]['name'] = 'pci_0000_b3_00_0'
        pci_device_report3[-2]['pciaddr'] = '0000:b3:00.0'
        pci_device_report3[-1]['name'] = 'pci_0000_b7_00_0'
        pci_device_report3[-1]['pciaddr'] = '0000:b7:00.0'
        for pci_dev in pci_device_report3:
            pci_dev['fpga_n3000_reset'] = False

        self.service.pci_device_update_by_host(self.context, ihost['uuid'], pci_device_report3)

        # without reset, N3000 devices aren't created
        self.assertRaises(exception.ServerNotFound,
                    self.dbapi.pci_device_get, '0000:b3:00.0', ihost['id'])
        self.assertRaises(exception.ServerNotFound,
                    self.dbapi.pci_device_get, '0000:b7:00.0', ihost['id'])
        # removed ACC100 device
        self.assertRaises(exception.ServerNotFound,
                    self.dbapi.pci_device_get, '0000:b4:00.0', ihost['id'])

        # N3000 with reset is reported
        pci_device_report4 = self._create_test_pci_device_report()
        self.service.pci_device_update_by_host(self.context, ihost['uuid'], pci_device_report4)

        for pci_dev in pci_device_report4:
            db_dev = self.dbapi.pci_device_get(pci_dev['pciaddr'], ihost['id'])
            for key in pci_dev:
                self.assertEqual(pci_dev[key], db_dev[key])

    def test_pci_device_update_acc100_replacement_to_n3000_different_slot(self):
        """ Test if an update contains a FEC card replacement on a different PCI slot

        In AIO-SX it is possible to replace a N3000 to ACC100 (or vice-versa). This test checks if
        the previous FEC card entry are erased if the PCI address of the new card is installed on a
        different address than the old card
        """
        mock_is_aio_simplex_system = mock.MagicMock()
        p3 = mock.patch('sysinv.common.utils.is_aio_simplex_system', mock_is_aio_simplex_system)
        p3.start().return_value = True
        self.addCleanup(p3.stop)

        # Create controller-0 node
        config_uuid = str(uuid.uuid4())
        ihost = self._create_test_ihost(
            hostname='controller-0', mgmt_mac="1a:2a:3a:4a:5a:6a", uuid=str(uuid.uuid4()),
            personality=constants.CONTROLLER, config_status=None, config_applied=config_uuid,
            config_target=config_uuid, invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED, operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        # create new dev with N3000 already reset
        pci_device_report1 = self._create_test_pci_device_report()
        self.service.pci_device_update_by_host(self.context, ihost['uuid'], pci_device_report1)

        # ACC100 reports on a different slot as N3000 is removed
        pci_device_report2 = self._create_test_pci_device_report(True)
        pci_device_report2[-1]['name'] = 'pci_0000_c4_00_0'
        pci_device_report2[-1]['pciaddr'] = '0000:c4:00.0'

        self.service.pci_device_update_by_host(self.context, ihost['uuid'], pci_device_report2)

        self.assertRaises(exception.ServerNotFound,
                    self.dbapi.pci_device_get, '0000:b2:00.0', ihost['id'])
        self.assertRaises(exception.ServerNotFound,
                    self.dbapi.pci_device_get, '0000:b4:00.0', ihost['id'])
        for pci_dev in pci_device_report2:
            db_dev = self.dbapi.pci_device_get(pci_dev['pciaddr'], ihost['id'])
            for key in pci_dev:
                self.assertEqual(pci_dev[key], db_dev[key])

    def test_pci_device_update_N3000_cleanup_stale_non_AIOSX(self):

        mock_is_aio_simplex_system = mock.MagicMock()
        p3 = mock.patch('sysinv.common.utils.is_aio_simplex_system', mock_is_aio_simplex_system)
        p3.start().return_value = False
        self.addCleanup(p3.stop)

        # Create controller-0 node
        config_uuid = str(uuid.uuid4())
        ihost = self._create_test_ihost(
            hostname='controller-0', mgmt_mac="1a:2a:3a:4a:5a:6a", uuid=str(uuid.uuid4()),
            personality=constants.CONTROLLER, config_status=None, config_applied=config_uuid,
            config_target=config_uuid, invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED, operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        # create new dev with N3000 already reset but add invalid addresses so they simulate
        # a database with both valid and invalid addresses from a possible situation from an upgrade
        pci_device_report1 = self._create_test_pci_device_report()
        pci_device_report1 += [copy.deepcopy(pci_device_report1[-2]),
                               copy.deepcopy(pci_device_report1[-1])]

        pci_device_report1[-2]['name'] = 'pci_0000_b3_00_0'
        pci_device_report1[-2]['pciaddr'] = '0000:b3:00.0'
        pci_device_report1[-1]['name'] = 'pci_0000_b7_00_0'
        pci_device_report1[-1]['pciaddr'] = '0000:b7:00.0'
        self.service.pci_device_update_by_host(self.context, ihost['uuid'], pci_device_report1)

        pci_device_report2 = self._create_test_pci_device_report()
        self.service.pci_device_update_by_host(self.context, ihost['uuid'],
                                               pci_device_report2, True)
        self.assertRaises(exception.ServerNotFound,
                    self.dbapi.pci_device_get, '0000:b3:00.0', ihost['id'])
        self.assertRaises(exception.ServerNotFound,
                    self.dbapi.pci_device_get, '0000:b7:00.0', ihost['id'])
        for pci_dev in pci_device_report2:
            db_dev = self.dbapi.pci_device_get(pci_dev['pciaddr'], ihost['id'])
            for key in pci_dev:
                self.assertEqual(pci_dev[key], db_dev[key])

    def test_inumas_update_by_ihost(self):
        # Create compute-0 node
        config_uuid = str(uuid.uuid4())
        ihost = self._create_test_ihost(
            personality=constants.WORKER,
            hostname='compute-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )
        host_uuid = ihost['uuid']
        host_id = ihost['id']
        utils.create_test_node(id=1, numa_node=0, forihostid=host_id)
        utils.create_test_node(id=2, numa_node=1, forihostid=host_id)
        port1 = utils.create_test_ethernet_port(
            id=1, name="port1", host_id=host_id,
            interface_id="1122", mac='08:00:27:43:60:11', numa_node=3)
        self.assertEqual(port1['node_id'], None)
        inuma_dict_array = [{'numa_node': 1}, {'numa_node': 3}]
        self.service.inumas_update_by_ihost(self.context, host_uuid, inuma_dict_array)
        updated_port = self.dbapi.ethernet_port_get(port1['uuid'], host_id)

        self.assertEqual(updated_port['node_id'], 3)

    def test_fpga_device_update_by_host(self):
        # Create compute-0 node
        config_uuid = str(uuid.uuid4())
        ihost = self._create_test_ihost(
            personality=constants.WORKER,
            hostname='compute-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )
        host_uuid = ihost['uuid']
        host_id = ihost['id']
        PCI_DEV_1 = {'uuid': str(uuid.uuid4()),
                     'name': 'pci_dev_1',
                     'pciaddr': '0000:0b:01.0',
                     'pclass_id': '060100',
                     'pvendor_id': '8086',
                     'pdevice_id': '0443',
                     'enabled': True,
                     'fpga_n3000_reset': True}
        PCI_DEV_2 = {'uuid': str(uuid.uuid4()),
                     'name': 'pci_dev_2',
                     'pciaddr': '0000:0c:01.0',
                     'pclass_id': '012000',
                     'pvendor_id': '8086',
                     'pdevice_id': '0b30',
                     'enabled': True,
                     'fpga_n3000_reset': True}
        pci_device_dict_array = [PCI_DEV_1, PCI_DEV_2]

        # create new PCI dev
        self.service.pci_device_update_by_host(self.context, host_uuid, pci_device_dict_array)

        dev = self.dbapi.pci_device_get(PCI_DEV_1['pciaddr'], host_id)
        for key in PCI_DEV_1:
            self.assertEqual(dev[key], PCI_DEV_1[key])

        dev = self.dbapi.pci_device_get(PCI_DEV_2['pciaddr'], host_id)
        for key in PCI_DEV_2:
            self.assertEqual(dev[key], PCI_DEV_2[key])

        FPGA_DEV_1 = {
            'pciaddr': PCI_DEV_1['pciaddr'],
            'bmc_build_version': 'D.2.0.6',
            'bmc_fw_version': 'D.2.0.21',
            'retimer_a_version': '101c.1064',
            'retimer_b_version': '0000.0000',
            'boot_page': 'user',
            'bitstream_id': '0x2383A62A010504',
            'root_key': '0x2973c55fc739e8181b16b9b51b786a39c0860159df8fb94652b0fbca87223bc7',
            'revoked_key_ids': '2,10,50-51',
        }
        fpga_device_dict_array = [FPGA_DEV_1]

        # Create new FPGA device.
        self.service.fpga_device_update_by_host(self.context, host_uuid,
                                                fpga_device_dict_array)
        dev = self.dbapi.fpga_device_get(FPGA_DEV_1['pciaddr'], host_id)
        for key in FPGA_DEV_1:
            self.assertEqual(dev[key], FPGA_DEV_1[key])

        # Update existing FPGA device.
        fpga_dev_dict_update = {
            'pciaddr': FPGA_DEV_1['pciaddr'],
            'bmc_build_version': 'D.2.0.7',
            'bmc_fw_version': 'D.2.0.22',
            'retimer_a_version': '101c.105c',
            'retimer_b_version': '0000.0000',
            'boot_page': 'factory',
            'bitstream_id': '0x2383A62A010504',
            'root_key': '',
            'revoked_key_ids': '',
        }
        fpga_dev_dict_update_array = [fpga_dev_dict_update]
        self.service.fpga_device_update_by_host(self.context, host_uuid,
                                                fpga_dev_dict_update_array)
        dev = self.dbapi.fpga_device_get(FPGA_DEV_1['pciaddr'], host_id)
        for key in fpga_dev_dict_update:
            self.assertEqual(dev[key], fpga_dev_dict_update[key])

    def test_upload_rootca(self):
        file = os.path.join(os.path.dirname(__file__), "../api", "data",
                                'rootca-with-key.pem')
        with open(file, 'rb') as certfile:
            certfile.seek(0, os.SEEK_SET)
            f = certfile.read()

        self.mock_kube_delete_secret = mock.MagicMock()
        q = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_delete_secret',
            self.mock_kube_delete_secret)
        q.start()
        self.addCleanup(q.stop)

        self.mock_kube_get_secret = mock.MagicMock()
        q = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_get_secret',
            self.mock_kube_get_secret)
        self.mock_kube_get_secret.return_value = FakeSecret(f)
        q.start()
        self.addCleanup(q.stop)
        utils.create_test_kube_rootca_update(state=kubernetes.KUBE_ROOTCA_UPDATE_STARTED)
        file = os.path.join(os.path.dirname(__file__), "../api", "data",
                                'rootca-with-key.pem')
        with open(file, 'rb') as certfile:
            certfile.seek(0, os.SEEK_SET)
            f = certfile.read()
            resp = self.service.save_kubernetes_rootca_cert(self.context, f)

        self.assertTrue(resp.get('success'))
        self.assertFalse(resp.get('error'))

    def test_upload_rootca_only_key(self):
        utils.create_test_kube_rootca_update(state=kubernetes.KUBE_ROOTCA_UPDATE_STARTED)
        file = os.path.join(os.path.dirname(__file__), "../api", "data",
                                'only_key.pem')

        with open(file, 'rb') as certfile:
            certfile.seek(0, os.SEEK_SET)
            f = certfile.read()
            resp = self.service.save_kubernetes_rootca_cert(self.context, f)

        self.assertTrue(resp.get('error'))
        self.assertIn("Failed to extract certificate from file", resp.get('error'))

    def test_upload_rootca_not_ca_certificate(self):
        utils.create_test_kube_rootca_update(state=kubernetes.KUBE_ROOTCA_UPDATE_STARTED)

        file = os.path.join(os.path.dirname(__file__), "../api", "data", 'cert-with-key-SAN.pem')
        with open(file, 'rb') as certfile:
            certfile.seek(0, os.SEEK_SET)
            f = certfile.read()
            resp = self.service.save_kubernetes_rootca_cert(self.context, f)
        self.assertTrue(resp.get('error'))
        self.assertIn("certificate in the file is not a CA certificate", resp.get('error'))

    def test_upload_rootca_not_in_progress(self):
        file = os.path.join(os.path.dirname(__file__), "../api", "data",
                                'rootca-with-key.pem')

        with open(file, 'rb') as certfile:
            certfile.seek(0, os.SEEK_SET)
            f = certfile.read()
            resp = self.service.save_kubernetes_rootca_cert(self.context, f)

        self.assertTrue(resp.get('error'))
        self.assertIn("Kubernetes root CA update not started", resp.get('error'))

    def test_upload_rootca_advanced_state(self):
        utils.create_test_kube_rootca_update(state=kubernetes.KUBE_ROOTCA_UPDATING_PODS_TRUSTBOTHCAS)
        file = os.path.join(os.path.dirname(__file__), "../api", "data",
                                'rootca-with-key.pem')

        with open(file, 'rb') as certfile:
            certfile.seek(0, os.SEEK_SET)
            f = certfile.read()
            resp = self.service.save_kubernetes_rootca_cert(self.context, f)

        self.assertTrue(resp.get('error'))
        self.assertIn("new root CA certificate already exists", resp.get('error'))

    def test_generate_rootca(self):
        file = os.path.join(os.path.dirname(__file__), "../api", "data",
                                'rootca-with-key.pem')
        with open(file, 'rb') as certfile:
            certfile.seek(0, os.SEEK_SET)
            f = certfile.read()

        self.mock_kube_get_secret = mock.MagicMock()
        q = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_get_secret',
            self.mock_kube_get_secret)
        self.mock_kube_get_secret.return_value = FakeSecret(f)
        q.start()
        self.addCleanup(q.stop)

        utils.create_test_kube_rootca_update(state=kubernetes.KUBE_ROOTCA_UPDATE_STARTED)
        resp = self.service.generate_kubernetes_rootca_cert(self.context, {}, None)
        self.assertTrue(resp.get('success'))

    def test_generate_rootca_not_in_progress(self):
        resp = self.service.generate_kubernetes_rootca_cert(self.context, {}, None)
        self.assertFalse(resp.get('success'))
        self.assertTrue(resp.get('error'))
        self.assertIn("Kubernetes root CA update not started", resp.get('error'))

    def test_generate_rootca_advanced_state(self):
        utils.create_test_kube_rootca_update(state=kubernetes.KUBE_ROOTCA_UPDATED_PODS_TRUSTBOTHCAS)
        resp = self.service.generate_kubernetes_rootca_cert(self.context, {}, None)
        self.assertFalse(resp.get('success'))
        self.assertTrue(resp.get('error'))
        self.assertIn("A new root CA certificate already exists", resp.get('error'))

    def test_device_update_image_status(self):

        mock_host_device_image_update_next = mock.MagicMock()
        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager.host_device_image_update_next',
            mock_host_device_image_update_next)
        p.start()
        self.addCleanup(p.stop)

        # Create compute-0 node
        ihost = self._create_test_ihost(
            personality=constants.WORKER,
            hostname='compute-0',
            uuid=str(uuid.uuid4()),
        )

        host_uuid = ihost.uuid
        host_id = ihost.id

        # Make sure we start with this set to false.
        self.dbapi.ihost_update(host_uuid, {'reboot_needed': False})

        DEV_IMG_STATE = {
            'host_id': host_id,
            'pcidevice_id': 5,
            'image_id': 11,
            'status': '',
        }
        device_image_state = self.dbapi.device_image_state_create(
            DEV_IMG_STATE)
        for key in DEV_IMG_STATE:
            self.assertEqual(device_image_state[key], DEV_IMG_STATE[key])

        # set status to "in-progress"
        self.service.device_update_image_status(self.context,
            host_uuid, device_image_state.uuid,
            dconstants.DEVICE_IMAGE_UPDATE_IN_PROGRESS)

        mock_host_device_image_update_next.assert_not_called()

        device_image_state = self.dbapi.device_image_state_get(
            device_image_state.id)
        self.assertEqual(device_image_state.status,
                         dconstants.DEVICE_IMAGE_UPDATE_IN_PROGRESS)
        ihost = self.dbapi.ihost_get(host_id)
        self.assertEqual(ihost.reboot_needed, False)

        # set status to "completed"
        self.service.device_update_image_status(self.context,
            host_uuid, device_image_state.uuid,
            dconstants.DEVICE_IMAGE_UPDATE_COMPLETED)

        mock_host_device_image_update_next.assert_called_with(
            self.context, host_uuid)

        device_image_state = self.dbapi.device_image_state_get(
            device_image_state.id)
        self.assertEqual(device_image_state.status,
                         dconstants.DEVICE_IMAGE_UPDATE_COMPLETED)
        ihost = self.dbapi.ihost_get(host_id)
        self.assertEqual(ihost.reboot_needed, True)

    def test_update_dnsmasq_config(self):
        mock_config_update_hosts = mock.MagicMock()
        mock_config_apply_runtime_manifest = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager._config_update_hosts',
                       mock_config_update_hosts)
        p.start().return_value = '1234'
        self.addCleanup(p.stop)
        p2 = mock.patch('sysinv.conductor.manager.ConductorManager._config_apply_runtime_manifest',
                        mock_config_apply_runtime_manifest)
        p2.start()
        self.addCleanup(p2.stop)
        self.service.update_dnsmasq_config(self.context)
        personalities = [constants.CONTROLLER]
        config_dict = {
            "personalities": personalities,
            "classes": ['platform::dns::dnsmasq::runtime'],
        }
        mock_config_apply_runtime_manifest.assert_called_with(mock.ANY, '1234', config_dict)

    def test_update_ldap_client_config(self):
        mock_config_update_hosts = mock.MagicMock()
        mock_config_apply_runtime_manifest = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager._config_update_hosts',
                       mock_config_update_hosts)
        p.start().return_value = '1234'
        self.addCleanup(p.stop)
        p2 = mock.patch('sysinv.conductor.manager.ConductorManager._config_apply_runtime_manifest',
                        mock_config_apply_runtime_manifest)
        p2.start()
        self.addCleanup(p2.stop)
        self.service.update_ldap_client_config(self.context)
        personalities = [constants.CONTROLLER,
                         constants.WORKER,
                         constants.STORAGE]
        config_dict = {
            "personalities": personalities,
            "classes": ['platform::ldap::client::runtime',
                        'platform::sssd::domain::runtime']
        }
        mock_config_apply_runtime_manifest.assert_called_with(mock.ANY, '1234', config_dict)

    def test_update_keystone_password(self):
        KEYSTONE_USER_PASSWORD_UPDATE = {
            "sysinv": "openstack::keystone::sysinv::password::runtime",
            "admin": "openstack::keystone::password::runtime",
            "barbican": "openstack::keystone::barbican::password::runtime",
            "fm": "openstack::keystone::fm::password::runtime",
            "mtce": "platform::mtce::runtime",
            "patching": "openstack::keystone::patching::password::runtime",
            "vim": "openstack::keystone::nfv::password::runtime"
        }

        mock_config_update_hosts = mock.MagicMock()
        mock_config_apply_runtime_manifest = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager._config_update_hosts',
                       mock_config_update_hosts)
        p.start().return_value = '1234'
        self.addCleanup(p.stop)
        p2 = mock.patch('sysinv.conductor.manager.ConductorManager._config_apply_runtime_manifest',
                        mock_config_apply_runtime_manifest)
        p2.start()
        self.addCleanup(p2.stop)
        self.service._update_keystone_password(self.context, "sysinv")
        personalities = [constants.CONTROLLER]
        config_dict = {
            "personalities": personalities,
            "classes": [KEYSTONE_USER_PASSWORD_UPDATE["sysinv"]]
        }
        mock_config_apply_runtime_manifest.assert_called_with(mock.ANY, '1234', config_dict)

    @mock.patch("oslo_context.context.RequestContext")
    def test_get_keystone_callback_endpoints(self, requestCtx):
        mock_config_update_hosts = mock.MagicMock()
        mock_config_apply_runtime_manifest = mock.MagicMock()
        mock_kube_app_AppOperator = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager._config_update_hosts',
                       mock_config_update_hosts)
        p.start().return_value = '1234'
        self.addCleanup(p.stop)

        p2 = mock.patch('sysinv.conductor.manager.ConductorManager._config_apply_runtime_manifest',
                        mock_config_apply_runtime_manifest)
        p2.start()
        self.addCleanup(p2.stop)

        p3 = mock.patch('sysinv.conductor.manager.kube_app.AppOperator',
                         mock_kube_app_AppOperator)
        p3.audit_local_registry_secrets = 'audit_local_registry_secrets_function'
        self.service._app = p3

        requestCtx.return_value = "context"

        endpoints = self.service._get_keystone_callback_endpoints()
        getContext = requestCtx(user='admin', tenant='admin', is_admin=True)

        config_dict = [{
            'context': getContext,
            'function': self.service._app.audit_local_registry_secrets,
            'user': 'sysinv'
        }, {
            'context': getContext,
            'function': self.service._update_keystone_password,
            'user': 'sysinv'
        }, {
            'context': getContext,
            'function': self.service._app.audit_local_registry_secrets,
            'user': 'admin'
        }, {
            'context': getContext,
            'function': self.service._update_keystone_password,
            'user': 'admin'
        }, {
            'context': getContext,
            'function': self.service._update_keystone_password,
            'user': 'barbican'
        }, {
            'context': getContext,
            'function': self.service._update_keystone_password,
            'user': 'fm'
        }, {
            'context': getContext,
            'function': self.service._update_keystone_password,
            'user': 'mtce'
        }, {
            'context': getContext,
            'function': self.service._update_keystone_password,
            'user': 'patching'
        }, {
            'context': getContext,
            'function': self.service._update_keystone_password,
            'user': 'usm'
        }, {
            'context': getContext,
            'function': self.service._update_keystone_password,
            'user': 'vim'
        }]

        self.assertEqual(endpoints, config_dict)

    @mock.patch("oslo_context.context.RequestContext")
    def test_get_keystone_callback_endpoints_system_controller(self, requestCtx):
        mock_config_update_hosts = mock.MagicMock()
        mock_config_apply_runtime_manifest = mock.MagicMock()
        mock_kube_app_AppOperator = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager._config_update_hosts',
                       mock_config_update_hosts)
        p.start().return_value = '1234'
        self.addCleanup(p.stop)

        p2 = mock.patch('sysinv.conductor.manager.ConductorManager._config_apply_runtime_manifest',
                        mock_config_apply_runtime_manifest)
        p2.start()
        self.addCleanup(p2.stop)

        p3 = mock.patch('sysinv.conductor.manager.kube_app.AppOperator',
                         mock_kube_app_AppOperator)
        p3.audit_local_registry_secrets = 'audit_local_registry_secrets_function'
        self.service._app = p3

        mock_dbapi = mock.MagicMock()
        mock_isystem = mock.MagicMock()
        mock_isystem.distributed_cloud_role = constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER
        mock_dbapi.isystem_get_one.return_value = mock_isystem
        self.service.dbapi = mock_dbapi

        requestCtx.return_value = "context"

        endpoints = self.service._get_keystone_callback_endpoints()
        getContext = requestCtx(user='admin', tenant='admin', is_admin=True)

        config_dict = [{
            "function": self.service._app.audit_local_registry_secrets,
            "context": getContext,
            "user": "sysinv"
        }, {
            "function": self.service._app.audit_local_registry_secrets,
            "context": getContext,
            "user": "admin"
        }, {
            "function": self.service._update_keystone_password,
            "context": getContext,
            "user": "admin"
        }]

        self.assertEqual(endpoints, config_dict)

    def _kernel_alarms_fix_keys(self, alarm_id, entity_id=None):
        """Create the nested dictionary keys if they are missing
           Prevents KeyError exceptions
        """
        if alarm_id not in self.kernel_alarms:
            self.kernel_alarms[alarm_id] = {}
        if entity_id and entity_id not in self.kernel_alarms[alarm_id]:
            self.kernel_alarms[alarm_id][entity_id] = None

    def _kernel_set_fault(self, fault):
        self._kernel_alarms_fix_keys(fault.alarm_id)
        self.kernel_alarms[fault.alarm_id][fault.entity_instance_id] = fault

    def _kernel_clear_fault(self, alarm_id, entity_id):
        self._kernel_alarms_fix_keys(alarm_id, entity_id)
        self.kernel_alarms[alarm_id][entity_id] = None

    def _kernel_get_faults_by_id(self, alarm_id):
        faults = []
        self._kernel_alarms_fix_keys(alarm_id)
        for fault in self.kernel_alarms[alarm_id].values():
            if fault is not None:
                faults.append(fault)
        if not faults:
            faults = None
        return faults

    def _is_kernel_alarm_raised(self, alarm_id, hostname):
        self._kernel_alarms_fix_keys(alarm_id)
        entity_id = None
        for key in self.kernel_alarms[alarm_id].keys():
            entity_id_partial = f"host={hostname}.kernel="
            if entity_id_partial in key:
                entity_id = key
                return self.kernel_alarms[alarm_id][entity_id] is not None

        return False

    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_apply_runtime_manifest')
    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_update_hosts')
    def test_kernel_runtime_manifests(self,
                                      mock_config_update_hosts,
                                      mock_config_apply_runtime_manifest):
        self._create_test_ihosts()
        ihost_hostname = 'controller-0'
        ihost = self.service.get_ihost_by_hostname(self.context,
                                                   ihost_hostname)
        ihost_uuid = ihost['uuid']
        personalities = [ihost['personality']]
        host_uuids = [ihost_uuid]
        config_dict = {
            "personalities": personalities,
            "host_uuids": host_uuids,
            "classes": [
                'platform::grub::kernel_image::runtime',
                'platform::config::file::subfunctions::lowlatency::runtime',
                'platform::compute::grub::runtime'
            ],
            'report_status': 'host_kernel_config'
        }
        config_uuid = '1234'
        mock_config_update_hosts.return_value = config_uuid
        self.service.kernel_runtime_manifests(context=self.context,
                                              ihost_uuid=ihost_uuid)

        mock_config_update_hosts.assert_called_once()
        mock_config_apply_runtime_manifest.assert_called_once_with(mock.ANY,
                                                                   config_uuid,
                                                                   config_dict,
                                                                   force=True)

    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_apply_runtime_manifest')
    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_update_hosts')
    def test_kernel_runtime_manifests_no_host(self,
                                              mock_config_update_hosts,
                                              mock_apply_runtime_manifest):
        ihost_uuid = str(uuid.uuid4())
        self.service.kernel_runtime_manifests(context=self.context,
                                              ihost_uuid=ihost_uuid)

        mock_config_update_hosts.assert_not_called()
        mock_apply_runtime_manifest.assert_not_called()

    def test_host_kernel_mismatch_alarm(self):
        """Test raising and clearing 100.121 alarm id"""
        alarm_id = fm_constants.FM_ALARM_ID_PROVISIONED_KERNEL_MISMATCH

        self.service.fm_api.set_fault.side_effect = self._kernel_set_fault
        self.service.fm_api.clear_fault.side_effect = self._kernel_clear_fault
        self.service.fm_api.get_faults_by_id.side_effect = \
            self._kernel_get_faults_by_id

        # Create controller-0
        ihost_hostname = 'controller-0'
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname=ihost_hostname,
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            mgmt_mac='00:11:22:33:44:55')

        ihost = self.service.get_ihost_by_hostname(self.context,
                                                   ihost_hostname)

        # before - no alarm
        self.assertFalse(self._is_kernel_alarm_raised(alarm_id, ihost_hostname))

        # simulate a running kernel update from controller-0 agent
        kernel_running = constants.KERNEL_LOWLATENCY
        self.service.report_kernel_running(self.context,
                                           ihost['uuid'],
                                           kernel_running)

        # after kernel=lowlatency update - alarm raised
        self.assertTrue(self._is_kernel_alarm_raised(alarm_id, ihost_hostname))

        # simulate a running kernel update from controller-0 agent
        kernel_running = constants.KERNEL_STANDARD
        self.service.report_kernel_running(self.context,
                                           ihost['uuid'],
                                           kernel_running)

        # after kernel=standard update - alarm cleared
        self.assertFalse(self._is_kernel_alarm_raised(alarm_id, ihost_hostname))

    def test_controllers_kernel_mismatch_alarms(self):
        """Test raising and clearing 100.120 alarm id"""
        alarm_id = fm_constants.FM_ALARM_ID_CONTROLLERS_KERNEL_MISMATCH

        self.service.fm_api.set_fault.side_effect = self._kernel_set_fault
        self.service.fm_api.clear_fault.side_effect = self._kernel_clear_fault
        self.service.fm_api.get_faults_by_id.side_effect = \
            self._kernel_get_faults_by_id

        # Create controller-0
        ihost_hostname0 = 'controller-0'
        config_uuid = str(uuid.uuid4())
        controller_0_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname=ihost_hostname0,
            uuid=controller_0_uuid,
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            mgmt_mac='00:11:22:33:44:55')

        # Create controller-1
        ihost_hostname1 = 'controller-1'
        config_uuid = str(uuid.uuid4())
        controller_1_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname=ihost_hostname1,
            uuid=controller_1_uuid,
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            mgmt_mac='22:44:33:55:11:66')

        # before - no alarm
        self.assertFalse(self._is_kernel_alarm_raised(alarm_id,
                                                      ihost_hostname0))
        self.assertFalse(self._is_kernel_alarm_raised(alarm_id,
                                                      ihost_hostname1))

        # simulate a running kernel update from controller-0 agent
        kernel_running = constants.KERNEL_STANDARD
        self.service.report_kernel_running(self.context,
                                           controller_0_uuid,
                                           kernel_running)

        self.assertFalse(self._is_kernel_alarm_raised(alarm_id,
                                                      ihost_hostname0))
        self.assertFalse(self._is_kernel_alarm_raised(alarm_id,
                                                      ihost_hostname1))

        # simulate a running kernel update from controller-1 agent
        kernel_running = constants.KERNEL_LOWLATENCY
        self.service.report_kernel_running(self.context,
                                           controller_1_uuid,
                                           kernel_running)

        # 2 alarms raised - for each controller
        self.assertTrue(self._is_kernel_alarm_raised(alarm_id,
                                                     ihost_hostname0))
        self.assertTrue(self._is_kernel_alarm_raised(alarm_id,
                                                     ihost_hostname1))

        # simulate a running kernel update from controller-0 agent
        kernel_running = constants.KERNEL_LOWLATENCY
        self.service.report_kernel_running(self.context,
                                           controller_0_uuid,
                                           kernel_running)

        # 2 alarms cleared - for each controller
        self.assertFalse(self._is_kernel_alarm_raised(alarm_id,
                                                      ihost_hostname0))
        self.assertFalse(self._is_kernel_alarm_raised(alarm_id,
                                                      ihost_hostname1))

    def get_app_object_moked_and_call_start(self):
        self.service.start()

        app = mock.MagicMock()
        app.name = "test_app"
        app.app_version = "1.0.0"
        app.app_metadata = {
            constants.APP_METADATA_DOWNGRADES: {
                constants.APP_METADATA_AUTO_DOWNGRADE: "True"
            }
        }

        return app

    # For unit test to get_app_bundle function, check that the return value of the
    # kube_get_kubelet_versions and KubeAppBundleDatabase.get_all functions were
    # mocked within the setUp function
    def test_get_app_bundle_for_update(self):
        app_moked = self.get_app_object_moked_and_call_start()

        # Test when k8s_version is None
        result = self.service._get_app_bundle_for_update(app_moked)
        # It should be if 1.1.0 auto_update was not false
        self.assertEqual(result.version, "1.0.5")

    def test_get_app_bundle_for_update_k8s_version(self):
        app_moked = self.get_app_object_moked_and_call_start()

        # Test when k8s_version is specified
        result = self.service._get_app_bundle_for_update(app_moked, k8s_version="v1.27.5")
        self.assertEqual(result.version, "1.2.5")
        # It was not version 1.2.5 because this metadata supports at most
        # version 1.20.0 of kubernets
        result = self.service._get_app_bundle_for_update(app_moked, k8s_version="v1.29.2")
        self.assertEqual(result.version, "1.2.0")

    def test_get_app_bundle_for_update_k8s_upgrade_timing(self):
        app_moked = self.get_app_object_moked_and_call_start()

        # Test with k8s_upgrade_timing key
        result = self.service._get_app_bundle_for_update(
            app_moked, k8s_version=None, k8s_upgrade_timing=constants.APP_METADATA_TIMING_PRE)
        # It should be if 1.1.0 auto_update was not false
        self.assertEqual(result.version, "1.0.5")

        # Test with k8s_upgrade_timing key
        result = self.service._get_app_bundle_for_update(
            app_moked, k8s_version=None, k8s_upgrade_timing=constants.APP_METADATA_TIMING_POST)
        # It should be if 1.1.0 auto_update was not false
        self.assertEqual(result.version, "1.0.5")

    def test_get_app_bundle_for_update_downgrade(self):
        app_moked = self.get_app_object_moked_and_call_start()

        # Using a higher app version than is available. The function must be able
        # to return the largest version available.
        app_moked.app_version = "1.2.3"
        result = self.service._get_app_bundle_for_update(app_moked)
        self.assertEqual(result.version, "1.1.0")

    def test_get_app_bundle_for_update_return_none(self):
        app_moked = self.get_app_object_moked_and_call_start()

        # Test when k8s_version lower than what is available.
        # This forces the return None
        result = self.service._get_app_bundle_for_update(app_moked, k8s_version="v1.17.0")
        self.assertEqual(result, None)

    @mock.patch('glob.glob')
    @mock.patch('sysinv.common.app_metadata.extract_bundle_metadata')
    @mock.patch('sysinv.conductor.manager.ConductorManager._update_cached_app_bundles_set')
    def test_populate_app_bundle_metadata(self,
                                          mock_update_cached_app_bundles_set,
                                          mock_extract_bundle_metadata,
                                          mock_glob):

        self.service._kube_app_bundle_storage = mock.MagicMock()
        mock_bundle_data = {"key": "value"}
        mock_extract_bundle_metadata.return_value = mock_bundle_data
        mock_glob.return_value = ["example_bundle.tgz"]

        self.service._populate_app_bundle_metadata()

        # Assert that the dependencies were called with the correct arguments
        mock_extract_bundle_metadata.assert_called_once_with("example_bundle.tgz")
        mock_update_cached_app_bundles_set.assert_called_once()
        self.service._kube_app_bundle_storage.create_all.assert_called_once_with(
            [mock_bundle_data])

    @mock.patch('sysinv.common.app_metadata.extract_bundle_metadata')
    def teste_add_app_bundle(self, mock_extract_bundle_metadata):

        self.service._kube_app_bundle_storage = mock.MagicMock()
        mock_bundle_data = {"key": "value"}
        mock_extract_bundle_metadata.return_value = mock_bundle_data
        self.service._add_app_bundle("full_bundle_path")

        # Assert that the dependencies were called with the correct arguments
        mock_extract_bundle_metadata.assert_called_once_with("full_bundle_path")
        self.service._kube_app_bundle_storage.create.assert_called_once_with(mock_bundle_data)

    def test_remove_app_bundle(self):

        self.service._kube_app_bundle_storage = mock.MagicMock()
        self.service._remove_app_bundle("full_bundle_path")

        # Assert that the dependencies were called with the correct arguments
        self.service._kube_app_bundle_storage\
            .destroy_by_file_path.assert_called_once_with("full_bundle_path")

    def test_update_cached_app_bundles_set(self):
        # Ensure that the cache is initially empty
        self.assertEqual(len(self.service._cached_app_bundle_set), 0)

        self.service.start()
        # Call the function to update the cache
        self.service._update_cached_app_bundles_set()

        # Ensure that the cache has been updated correctly
        expected_set = {"/path/to/bundle1",
                        "/path/to/bundle2",
                        "/path/to/bundle3",
                        "/path/to/bundle4"}
        self.assertEqual(self.service._cached_app_bundle_set, expected_set)

    @mock.patch('glob.glob')
    @mock.patch('sysinv.conductor.manager.ConductorManager._add_app_bundle')
    @mock.patch('sysinv.conductor.manager.ConductorManager._remove_app_bundle')
    @mock.patch('sysinv.conductor.manager.ConductorManager._update_cached_app_bundles_set')
    def test_update_app_bundles_storage(self,
                                        mock_update_cached_app_bundles_set,
                                        mock_remove_app_bundle,
                                        mock_add_app_bundle,
                                        mock_glob):

        self.service._cached_app_bundle_set = [
            "/path/to/bundle1",
            "/path/to/bundle2",
            "/path/to/bundle3",
            "/path/to/bundle4",
        ]
        bundle_path_list = [
            "/path/to/bundle1",
            "/path/to/bundle3",
            "/path/to/bundle4",
            "/path/to/bundle5",
        ]

        mock_glob.return_value = bundle_path_list
        self.service._update_app_bundles_storage()

        # For this test was remove /path/to/bundle3 and add /path/to/bundle5
        mock_add_app_bundle.assert_called_once_with("/path/to/bundle5")
        mock_remove_app_bundle.assert_called_once_with("/path/to/bundle2")

        # ou must call the _update_cached_app_bundles_set function to
        # update only 1 time
        mock_update_cached_app_bundles_set.assert_called_once()

    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_apply_runtime_manifest')
    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_update_hosts')
    def test_configure_stalld(self,
                              mock_config_update_hosts,
                              mock_config_apply_runtime_manifest):
        self._create_test_ihosts()
        hostname = 'compute-0'
        host = self.service.get_ihost_by_hostname(self.context, hostname)
        host_uuid = host['uuid']
        personalities = [host['personality']]
        host_uuids = [host_uuid]
        config_dict = {
            "personalities": personalities,
            "host_uuids": host_uuids,
            "classes": [
                'platform::stalld::runtime'
            ],
        }
        config_uuid = '1234'
        mock_config_update_hosts.return_value = config_uuid
        self.service.configure_stalld(context=self.context,
                                      host_uuid=host_uuid)

        mock_config_update_hosts.assert_called_once()
        mock_config_apply_runtime_manifest.assert_called_once_with(
            mock.ANY,
            config_uuid,
            config_dict)

    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_apply_runtime_manifest')
    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_update_hosts')
    def test_configure_stalld_host_not_found(self,
                              mock_config_update_hosts,
                              mock_config_apply_runtime_manifest):
        host_uuid = str(uuid.uuid4())
        self.service.configure_stalld(context=self.context,
                                      host_uuid=host_uuid)

        mock_config_update_hosts.assert_not_called()
        mock_config_apply_runtime_manifest.assert_not_called()


class ManagerTestCaseInternal(base.BaseHostTestCase):
    def setUp(self):
        super(ManagerTestCaseInternal, self).setUp()

        # Set up objects for testing
        self.service = manager.ConductorManager('test-host', 'test-topic')
        self.service.dbapi = dbapi.get_instance()

    def _create_test_ihost(self, **kwargs):
        # ensure the system ID for proper association
        kwargs['forisystemid'] = self.system['id']
        ihost_dict = utils.get_test_ihost(**kwargs)
        # Let DB generate ID if it isn't specified explicitly
        if 'id' not in kwargs:
            del ihost_dict['id']
        ihost = self.service.dbapi.ihost_create(ihost_dict)
        return ihost

    def create_ipv6_pools(self):
        mgmt_subnet6 = netaddr.IPNetwork('fd01::/64')
        oam_subnet6 = netaddr.IPNetwork('fd00::/64')
        cluster_host_subnet6 = netaddr.IPNetwork('fd02::/64')
        cluster_pod_subnet6 = netaddr.IPNetwork('fd03::/64')
        cluster_service_subnet6 = netaddr.IPNetwork('fd04::/112')
        multicast_subnet6 = netaddr.IPNetwork('ff08::1:1:0/124')
        storage_subnet6 = netaddr.IPNetwork('fd05::/64')
        admin_subnet6 = netaddr.IPNetwork('fd09::/64')
        self._create_test_address_pool(name="management-ipv6", subnet=mgmt_subnet6)
        self._create_test_address_pool(name="oam-ipv6", subnet=oam_subnet6)
        self._create_test_address_pool(name="cluster-host-ipv6", subnet=cluster_host_subnet6)
        self._create_test_address_pool(name="cluster-pod-ipv6", subnet=cluster_pod_subnet6)
        self._create_test_address_pool(name="cluster-service-ipv6", subnet=cluster_service_subnet6)
        self._create_test_address_pool(name="multicast-ipv6", subnet=multicast_subnet6)
        self._create_test_address_pool(name="storage-ipv6", subnet=storage_subnet6)
        self._create_test_address_pool(name="admin-ipv6", subnet=admin_subnet6)

    def test_remove_lease_for_address(self):
        # create test interface
        ihost = self._create_test_host(
            personality=constants.WORKER,
            administrative=constants.ADMIN_UNLOCKED)
        iface = utils.create_test_interface(
                ifname="test0",
                ifclass=constants.INTERFACE_CLASS_PLATFORM,
                forihostid=ihost.id,
                ihost_uuid=ihost.uuid)
        network = self.dbapi.network_get_by_type(constants.NETWORK_TYPE_MGMT)
        utils.create_test_interface_network(
            interface_id=iface.id,
            network_id=network.id)

        # create test address associated with interface
        address_name = cutils.format_address_name(ihost.hostname,
            network.type)
        self.dbapi.address_create({
            'name': address_name,
            'family': self.oam_subnet.version,
            'prefix': self.oam_subnet.prefixlen,
            'address': str(self.oam_subnet[24]),
            'interface_id': iface.id,
            'enable_dad': self.oam_subnet.version == 6
        })

        # stub the system i/o calls
        self.mock_objs = [
            mock.patch.object(
                manager.ConductorManager, '_find_local_interface_name',
                lambda x, y: iface.ifname),
            mock.patch('sysinv.common.utils.get_dhcp_cid',
                lambda x, y, z: None),
            mock.patch.object(
                manager.ConductorManager, '_dhcp_release',
                lambda a, b, c, d, e: None)
        ]

        for mock_obj in self.mock_objs:
            mock_obj.start()
            self.addCleanup(mock_obj.stop)

        self.service._remove_lease_for_address(ihost.hostname,
            constants.NETWORK_TYPE_MGMT)

    def test_configure_ihost_allocate_addresses_for_host(self):
        # Test skipped to prevent error message in Jenkins. Error thrown is:
        # in test_configure_ihost_allocate_addresses_for_host
        # with open(self.dnsmasq_hosts_file, 'w') as f:
        # IOError: [Errno 13] Permission denied: '/tmp/dnsmasq.hosts'
        # self.skipTest("Skipping to prevent failure notification on Jenkins")

        self.context = context.get_admin_context()
        self.service._generate_dnsmasq_hosts_file = mock.Mock()
        self.service._puppet = mock.Mock()
        self.service._update_pxe_config = mock.Mock()

        # create a basic ihost object
        ihost = self._create_test_ihost()

        self.create_ipv6_pools()

        net_mgmt = self.dbapi.network_get_by_type(constants.NETWORK_TYPE_MGMT)
        pool_mgmt6 = self.dbapi.address_pool_query({"name": "management-ipv6"})
        pool_mgmt4 = self.dbapi.address_pool_query({"name": "management-ipv4"})
        dbutils.create_test_network_addrpool(address_pool_id=pool_mgmt6.id,
                                             network_id=net_mgmt.id)

        net_clhost = self.dbapi.network_get_by_type(constants.NETWORK_TYPE_CLUSTER_HOST)
        pool_clhost6 = self.dbapi.address_pool_query({"name": "cluster-host-ipv6"})
        pool_clhost4 = self.dbapi.address_pool_query({"name": "cluster-host-ipv4"})
        dbutils.create_test_network_addrpool(address_pool_id=pool_clhost6.id,
                                             network_id=net_clhost.id)

        worker_name = 'newhost'
        ihost['mgmt_mac'] = '00:11:22:33:44:55'
        ihost['hostname'] = worker_name
        ihost['invprovision'] = 'unprovisioned'
        ihost['personality'] = 'worker'
        ihost['administrative'] = 'locked'
        ihost['operational'] = 'disabled'
        ihost['availability'] = 'not-installed'
        ihost['serialid'] = '1234567890abc'
        ihost['boot_device'] = 'sda'
        ihost['rootfs_device'] = 'sda'
        ihost['hw_settle'] = '0'
        ihost['sw_version'] = '0.0'
        ihost['install_output'] = 'text'
        ihost['console'] = 'ttyS0,115200'

        # Create the management addresses and associate them with unassigned address pools, to
        # test the _create_or_update_address function. The addresses are expected to be updated,
        # removed from the unassigned pool and assigned to the corresponding management pool. The
        # address pools are also expected to be updated.
        # The allocated IPv4 will conflict with the existing 'pool-addr-ipv4', so the later will be
        # used instead of a newly created one.
        # The IPv6 address will be retrieved by name ('newhost-mgmt') and family.

        objects = {constants.IPV4_FAMILY: {'main_pool': pool_mgmt4, 'addr_name': 'pool-addr-ipv4'},
                   constants.IPV6_FAMILY: {'main_pool': pool_mgmt6, 'addr_name': 'newhost-mgmt'}}

        for family, family_dict in objects.items():
            main_pool = family_dict['main_pool']
            other_pool = dbutils.create_test_address_pool(
                name='other-pool-ipv{}'.format(family),
                family=main_pool.family,
                network=main_pool.network,
                prefix=main_pool.prefix,
                ranges=main_pool.ranges)

            subnet = netaddr.IPNetwork(f"{main_pool.network}/{main_pool.prefix}")
            pool_addr = dbutils.create_test_address(
                name=family_dict['addr_name'],
                family=main_pool.family,
                address=str(subnet[5]),
                prefix=main_pool.prefix,
                address_pool_id=other_pool.id)

            self.dbapi.address_pool_update(other_pool.uuid, {'floating_address_id': pool_addr.id})

            family_dict['other_pool'] = other_pool
            family_dict['address'] = pool_addr

        self.dbapi.address_pool_update(pool_mgmt4.uuid, {'order': 'sequential'})

        self.service.configure_ihost(self.context, ihost)

        addr_mgmt4 = self.dbapi.address_get_by_name_and_family(
            f"{worker_name}-{constants.NETWORK_TYPE_MGMT}",
            constants.IPV4_FAMILY)
        self.assertEqual(addr_mgmt4.pool_uuid, pool_mgmt4.uuid)
        self.assertEqual(addr_mgmt4.family, pool_mgmt4.family)

        addr_mgmt6 = self.dbapi.address_get_by_name_and_family(
            f"{worker_name}-{constants.NETWORK_TYPE_MGMT}",
            constants.IPV6_FAMILY)
        self.assertEqual(addr_mgmt6.pool_uuid, pool_mgmt6.uuid)
        self.assertEqual(addr_mgmt6.family, pool_mgmt6.family)

        addr_clhost4 = self.dbapi.address_get_by_name_and_family(
            f"{worker_name}-{constants.NETWORK_TYPE_CLUSTER_HOST}",
            constants.IPV4_FAMILY)
        self.assertEqual(addr_clhost4.pool_uuid, pool_clhost4.uuid)

        addr_clhost6 = self.dbapi.address_get_by_name_and_family(
            f"{worker_name}-{constants.NETWORK_TYPE_CLUSTER_HOST}",
            constants.IPV6_FAMILY)
        self.assertEqual(addr_clhost6.pool_uuid, pool_clhost6.uuid)

        for family_dict in objects.values():
            main_pool = self.dbapi.address_pool_get(family_dict['main_pool'].id)
            other_pool = self.dbapi.address_pool_get(family_dict['other_pool'].id)
            address = self.dbapi.address_get(family_dict['address'].id)
            self.assertEqual(f"{worker_name}-mgmt", address.name)
            self.assertEqual(main_pool.uuid, address.pool_uuid)
            self.assertIsNone(other_pool.floating_address_id)

    def test_configure_ihost_allocate_addresses_for_host_no_net_pool_object(self):
        # the data-migration for upgrade was not implemented yet for the dual-stack feature
        # this test aims to validate this condition
        # self.skipTest("Skipping to prevent failure notification on Jenkins")

        self.context = context.get_admin_context()
        self.service._generate_dnsmasq_hosts_file = mock.Mock()
        self.service._puppet = mock.Mock()
        self.service._update_pxe_config = mock.Mock()

        # create a basic ihost object
        ihost = self._create_test_ihost()

        self.create_ipv6_pools()

        pool_mgmt4 = self.dbapi.address_pool_query({"name": "management-ipv4"})
        pool_clhost4 = self.dbapi.address_pool_query({"name": "cluster-host-ipv4"})
        net_pools = self.dbapi.network_addrpool_get_all()
        for net_pool in net_pools:
            self.dbapi.network_addrpool_destroy(net_pool.uuid)

        worker_name = 'newhost'
        ihost['mgmt_mac'] = '00:11:22:33:44:55'
        ihost['hostname'] = worker_name
        ihost['invprovision'] = 'unprovisioned'
        ihost['personality'] = 'worker'
        ihost['administrative'] = 'locked'
        ihost['operational'] = 'disabled'
        ihost['availability'] = 'not-installed'
        ihost['serialid'] = '1234567890abc'
        ihost['boot_device'] = 'sda'
        ihost['rootfs_device'] = 'sda'
        ihost['hw_settle'] = '0'
        ihost['sw_version'] = '0.0'
        ihost['install_output'] = 'text'
        ihost['console'] = 'ttyS0,115200'

        self.assertRaises(exception.AddressNotFoundByNameAndFamily,
                          self.dbapi.address_get_by_name_and_family,
                          f"{worker_name}-{constants.NETWORK_TYPE_MGMT}",
                          constants.IPV4_FAMILY)

        self.assertRaises(exception.AddressNotFoundByNameAndFamily,
                          self.dbapi.address_get_by_name_and_family,
                          f"{worker_name}-{constants.NETWORK_TYPE_CLUSTER_HOST}",
                          constants.IPV6_FAMILY)

        self.service.configure_ihost(self.context, ihost)

        addr_mgmt4 = self.dbapi.address_get_by_name_and_family(
            f"{worker_name}-{constants.NETWORK_TYPE_MGMT}",
            constants.IPV4_FAMILY)
        self.assertEqual(addr_mgmt4.pool_uuid, pool_mgmt4.uuid)
        self.assertEqual(addr_mgmt4.family, pool_mgmt4.family)

        self.assertRaises(exception.AddressNotFoundByNameAndFamily,
                          self.dbapi.address_get_by_name_and_family,
                          f"{worker_name}-{constants.NETWORK_TYPE_MGMT}",
                          constants.IPV6_FAMILY)

        addr_clhost4 = self.dbapi.address_get_by_name_and_family(
            f"{worker_name}-{constants.NETWORK_TYPE_CLUSTER_HOST}",
            constants.IPV4_FAMILY)
        self.assertEqual(addr_clhost4.pool_uuid, pool_clhost4.uuid)

        self.assertRaises(exception.AddressNotFoundByNameAndFamily,
                          self.dbapi.address_get_by_name_and_family,
                          f"{worker_name}-{constants.NETWORK_TYPE_CLUSTER_HOST}",
                          constants.IPV6_FAMILY)

    def test_mgmt_ip_set_by_ihost(self):
        p = mock.patch('sysinv.conductor.manager.ConductorManager._generate_dnsmasq_hosts_file')
        self.mock_manager_generate_dnsmasq_hosts_file = p.start()
        self.addCleanup(p.stop)

        controller0 = self._create_test_host(constants.CONTROLLER, unit=0)

        c0_mgmt0 = dbutils.create_test_interface(
            ifname='c0_mgm0',
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            forihostid=controller0.id,
            ihost_uuid=controller0.uuid)

        mgmt_network = self._find_network_by_type(constants.NETWORK_TYPE_MGMT)
        mgmt_pool = self._find_network_address_pools(mgmt_network.id)[0]

        subnet = netaddr.IPNetwork('{}/{}'.format(mgmt_pool.network, mgmt_pool.prefix))

        other_pool = dbutils.create_test_address_pool(
            name='existing-pool',
            family=subnet.version,
            network=str(subnet.ip),
            prefix=subnet.prefixlen,
            ranges=[[str(subnet[1]), str(subnet[-1])]])

        dbutils.create_test_interface_network(interface_id=c0_mgmt0.id,
                                              network_id=mgmt_network.id)

        self.dbapi.address_update(mgmt_pool.controller0_address_id,
                                  {'address_pool_id': other_pool.id,
                                   'name': 'existing-pool-c0'})
        self.dbapi.address_pool_update(
            mgmt_pool.id, {'controller0_address_id': None})
        self.dbapi.address_pool_update(
            other_pool.id, {'controller0_address_id': mgmt_pool.controller0_address_id})

        self.service.mgmt_ip_set_by_ihost(None, controller0.uuid, c0_mgmt0.id,
                                          mgmt_pool.controller0_address)

        updated_address = self.dbapi.address_get(mgmt_pool.controller0_address_id)
        self.assertEqual(mgmt_pool.uuid, updated_address.pool_uuid)
        self.assertEqual('controller-0-mgmt', updated_address.name)
        self.assertEqual(c0_mgmt0.id, updated_address.interface_id)

        updated_mgmt_pool = self.dbapi.address_pool_get(mgmt_pool.id)
        self.assertEqual(updated_address.id, updated_mgmt_pool.controller0_address_id)

        updated_other_pool = self.dbapi.address_pool_get(other_pool.id)
        self.assertIsNone(updated_other_pool.controller0_address_id)

        self.mock_manager_generate_dnsmasq_hosts_file.assert_called()

    def test_check_nodes_stable(self):
        host = self._create_test_host(constants.CONTROLLER,
                                      availability=constants.AVAILABILITY_INTEST,
                                      task="task",
                                      vim_progress_status=None)

        p = mock.patch.object(manager, 'LOG')
        mock_log = p.start()
        mock_log.warn.return_value = None
        self.addCleanup(p.stop)

        result = self.service.check_nodes_stable()
        self.assertEqual(False, result)

        self.dbapi.ihost_update(host.id, {'availability': constants.AVAILABILITY_AVAILABLE})

        result = self.service.check_nodes_stable()
        self.assertEqual(False, result)

        self.dbapi.ihost_update(host.id, {'task': ''})

        result = self.service.check_nodes_stable()
        self.assertEqual(False, result)
        mock_log.warn.assert_not_called()

        self.dbapi.ihost_update(host.id, {'vim_progress_status': ''})

        result = self.service.check_nodes_stable()
        self.assertEqual(False, result)

        self.dbapi.ihost_update(host.id, {'vim_progress_status': constants.VIM_SERVICES_ENABLED})

        result = self.service.check_nodes_stable()
        self.assertEqual(True, result)

        q = mock.patch.object(self.service.dbapi, 'ihost_get_list')
        mock_ihost_get_list = q.start()
        mock_ihost_get_list.side_effect = exception.SysinvException()
        self.addCleanup(q.stop)

        result = self.service.check_nodes_stable()
        self.assertEqual(False, result)
        mock_log.warn.assert_called_once()

    @mock.patch('os.system')
    def test_generate_dnsmasq_hosts_file_concurrency(self, mock_os_system):
        lock = threading.Lock()
        running = 0
        collisions = 0

        def os_system_side_effect(command):
            nonlocal lock
            nonlocal running
            nonlocal collisions

            with lock:
                prev = running
                running += 1

            if prev > 0:
                collisions += 1

            sleep(0.5)

            with lock:
                running -= 1

        def function_caller():
            try:
                self.service._generate_dnsmasq_hosts_file()
            except Exception:
                pass

        mock_os_system.side_effect = os_system_side_effect

        threads = [threading.Thread(target=function_caller) for i in range(3)]

        for thr in threads:
            thr.start()

        function_caller()

        for thr in threads:
            thr.join()

        self.assertEqual(0, collisions)
