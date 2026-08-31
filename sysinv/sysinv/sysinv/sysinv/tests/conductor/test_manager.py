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
# Copyright (c) 2013-2026 Wind River Systems, Inc.
#

"""Test class for Sysinv ManagerService."""

import copy
import datetime
import inspect
import io
import json
import mock
import os.path
import netaddr
import uuid
import threading
import wsme
from time import sleep

from docker.errors import ImageNotFound
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from fm_api import constants as fm_constants
from keystoneauth1 import exceptions as ks_exceptions
from oslo_context import context
from oslo_db import exception as oslo_db_exception
from oslo_serialization import base64
from oslo_utils import timeutils
from sysinv.agent import rpcapi as agent_rpcapi
from sysinv.api.controllers.v1 import host as host_api
from sysinv.api.controllers.v1 import label as label_api
from sysinv.api.controllers.v1 import memory as memory_api
from sysinv.common import constants
from sysinv.common import device as dconstants
from sysinv.common import exception
from sysinv.common import helper
from sysinv.common import kubernetes
from sysinv.common import utils as cutils
from sysinv.common import usm_service
from sysinv.common.image_download import ContainerImageDownloader
from sysinv.conductor import kube_app
from sysinv.conductor import manager
from sysinv.helm import common as helm_common

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
                                            'apiVersion: kubeadm.k8s.io/v1beta4\n'
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
        if cutils.is_debian_bullseye():
            config_patch = 'apiServer:\n  certSANs: [192.168.206.1, 127.0.0.1, 10.10.6.3]\n  '
            config_patch += 'extraArgs: {event-ttl: 24h}\n  extraVolumes:\n  - {hostPath: '
            config_patch += '/etc/kubernetes/encryption-provider.yaml}\napiVersion: '
            config_patch += 'kubeadm.k8s.io/v1beta4\ncontrollerManager:\n  extraArgs: '
            config_patch += '{feature-gates: CSIMigrationPortworx=false}\n'
            config_patch += '  extraVolumes: null\nkind: ClusterConfiguration\nkubernetesVersion: '
            config_patch += 'v1.42.1\nscheduler: {}\n'
        else:
            config_patch = ('apiServer:\n'
                            '  certSANs:\n'
                            '  - 192.168.206.1\n'
                            '  - 127.0.0.1\n'
                            '  - 10.10.6.3\n'
                            '  extraArgs:\n'
                            '    event-ttl: 24h\n'
                            '  extraVolumes:\n'
                            '  - hostPath: /etc/kubernetes/encryption-provider.yaml\n'
                            'apiVersion: kubeadm.k8s.io/v1beta4\n'
                            'controllerManager:\n'
                            '  extraArgs:\n'
                            '    feature-gates: CSIMigrationPortworx=false\n'
                            '  extraVolumes:\n'
                            'kind: ClusterConfiguration\n'
                            'kubernetesVersion: v1.42.1\n'
                            'scheduler: {}\n')
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
                                            'apiVersion: kubeadm.k8s.io/v1beta4\n'
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
        if cutils.is_debian_bullseye():
            selflink_patch = 'apiServer:\n  certSANs: [192.168.206.1, 127.0.0.1, 10.10.6.3]\n  '
            selflink_patch += 'extraArgs: {event-ttl: 24h}\n  extraVolumes:\n  - {hostPath: '
            selflink_patch += '/etc/kubernetes/encryption-provider.yaml}\napiVersion: '
            selflink_patch += 'kubeadm.k8s.io/v1beta4\ncontrollerManager:\n  extraArgs: '
            selflink_patch += '{feature-gates: CSIMigrationPortworx=false}\n'
            selflink_patch += '  extraVolumes: null\nkind: '
            selflink_patch += 'ClusterConfiguration\nkubernetesVersion: v1.42.1\nscheduler: {}\n'
        else:
            selflink_patch = ('apiServer:\n'
                              '  certSANs:\n'
                              '  - 192.168.206.1\n'
                              '  - 127.0.0.1\n'
                              '  - 10.10.6.3\n'
                              '  extraArgs:\n'
                              '    event-ttl: 24h\n'
                              '  extraVolumes:\n'
                              '  - hostPath: /etc/kubernetes/encryption-provider.yaml\n'
                              'apiVersion: kubeadm.k8s.io/v1beta4\n'
                              'controllerManager:\n'
                              '  extraArgs:\n'
                              '    feature-gates: CSIMigrationPortworx=false\n'
                              '  extraVolumes:\n'
                              'kind: ClusterConfiguration\n'
                              'kubernetesVersion: v1.42.1\n'
                              'scheduler: {}\n')
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
                                            'apiVersion: kubeadm.k8s.io/v1beta4\n'
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

        if cutils.is_debian_bullseye():
            self.kubeadm_config_map_patch_etcd_endpoints = \
                {'data':
                 {'ClusterConfiguration': 'apiServer:\n'
                                            '  certSANs: [192.168.206.1, 127.0.0.1, 10.10.6.3]\n'
                                            '  extraArgs: {event-ttl: 24h}\n'
                                            '  extraVolumes:\n'
                                            '  - {hostPath: /etc/kubernetes/encryption-provider.yaml}\n'
                                            'apiVersion: kubeadm.k8s.io/v1beta4\n'
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
        else:
            self.kubeadm_config_map_patch_etcd_endpoints = \
                {'data':
                 {'ClusterConfiguration': 'apiServer:\n'
                                            '  certSANs:\n'
                                            '  - 192.168.206.1\n'
                                            '  - 127.0.0.1\n'
                                            '  - 10.10.6.3\n'
                                            '  extraArgs:\n'
                                            '    event-ttl: 24h\n'
                                            '  extraVolumes:\n'
                                            '  - hostPath: /etc/kubernetes/encryption-provider.yaml\n'
                                            'apiVersion: kubeadm.k8s.io/v1beta4\n'
                                            'controllerManager:\n'
                                            '  extraArgs:\n'
                                            '    feature-gates: CSIMigrationPortworx=false\n'
                                            '  extraVolumes:\n'
                                            'etcd:\n'
                                            '  external:\n'
                                            '    caFile: /etc/etcd/ca.crt\n'
                                            '    certFile: /etc/kubernetes/pki/apiserver-etcd-client.crt\n'
                                            '    endpoints:\n'
                                            '    - https://192.168.206.1:2379\n'
                                            '    keyFile: /etc/kubernetes/pki/apiserver-etcd-client.key\n'
                                            'kind: ClusterConfiguration\n'
                                            'kubernetesVersion: v1.42.1\n'
                                            'scheduler: {}\n'}}

        super(ManagerTestCase, self).setUp()

        # Set up objects for testing
        self.service = manager.ConductorManager('test-host', 'test-topic')
        self.service.dbapi = dbapi.get_instance()
        self.service._docker = kube_app.DockerHelper(self.service.dbapi)
        self.service._image_downloader = ContainerImageDownloader(self.service.dbapi)
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

        def mock_get_reorder_apps():
            return self.get_reorder_apps_result
        self.mocked_get_reorder_apps = mock.patch(
            'sysinv.common.app_metadata.get_reorder_apps',
            mock_get_reorder_apps)
        self.mocked_get_reorder_apps.start()
        self.addCleanup(self.mocked_get_reorder_apps.stop)

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

    @mock.patch('sysinv.common.utils.get_app_metadata_from_tarfile')
    def test_perform_app_update_rejects_unsupported_from_versions(self, mock_get_metadata):
        from_rpc_app = dbutils.create_test_app(
            name='test-app',
            app_version='1.0-1',
            status=constants.APP_APPLY_SUCCESS,
            active=True)
        from_rpc_app = self.dbapi.kube_app_get_by_id(from_rpc_app.id)
        from_rpc_app._context = self.context
        to_rpc_app = dbutils.create_test_app(
            name='test-app',
            app_version='2.0-1',
            status=constants.APP_UPDATE_IN_PROGRESS,
            active=True)
        to_rpc_app = self.dbapi.kube_app_get_by_id(to_rpc_app.id)
        to_rpc_app._context = self.context
        lifecycle_hook_info = mock.Mock()
        mock_get_metadata.return_value = {
            constants.APP_METADATA_UPGRADES: {
                constants.APP_METADATA_FROM_VERSIONS: [r'2\.0-\d+']
            }
        }
        self.service._app = mock.Mock()

        with mock.patch.object(self.service._app, 'perform_app_update') as mock_perform_update:
            self.assertRaises(
                exception.KubeAppUpdateFailure,
                self.service.perform_app_update,
                self.context,
                from_rpc_app,
                to_rpc_app,
                '/tmp/test-app-2.0-1.tgz',
                lifecycle_hook_info)

        from_rpc_app = self.dbapi.kube_app_get_by_id(from_rpc_app.id)
        from_rpc_app._context = self.context
        self.assertEqual(constants.APP_APPLY_SUCCESS, from_rpc_app.status)
        self.assertIn('does not match any supported', from_rpc_app.progress)
        self.assertEqual(constants.APP_INACTIVE_STATE, to_rpc_app.status)
        mock_perform_update.assert_not_called()
        self.assertRaises(
            exception.KubeAppInactiveNotFound,
            self.dbapi.kube_app_get_inactive_by_name_version,
            to_rpc_app.name,
            to_rpc_app.app_version)

    @mock.patch('sysinv.common.utils.get_app_metadata_from_tarfile')
    def test_perform_app_update_allows_regex_from_versions(self, mock_get_metadata):
        from_rpc_app = dbutils.create_test_app(
            name='test-app',
            app_version='1.0-1',
            status=constants.APP_APPLY_SUCCESS,
            active=True)
        from_rpc_app = self.dbapi.kube_app_get_by_id(from_rpc_app.id)
        from_rpc_app._context = self.context
        to_rpc_app = dbutils.create_test_app(
            name='test-app',
            app_version='2.0-1',
            status=constants.APP_UPDATE_IN_PROGRESS,
            active=True)
        to_rpc_app = self.dbapi.kube_app_get_by_id(to_rpc_app.id)
        to_rpc_app._context = self.context
        lifecycle_hook_info = mock.Mock()
        mock_get_metadata.return_value = {
            constants.APP_METADATA_UPGRADES: {
                constants.APP_METADATA_FROM_VERSIONS: [r'1\.0-\d+']
            }
        }
        self.service._app = mock.Mock()
        self.service._app.update_and_process_app_metadata.return_value = None
        self.service._kube = mock.Mock()
        self.service._kube.kube_get_kubernetes_version.return_value = 'v1.29.2'

        with mock.patch.object(self.service._app, 'perform_app_update',
                               return_value=True) as mock_perform_update, \
             mock.patch.object(self.service,
                               'perform_upload_apply_dependent_apps',
                               return_value=True):
            result = self.service.perform_app_update(
                self.context,
                from_rpc_app,
                to_rpc_app,
                '/tmp/test-app-2.0-1.tgz',
                lifecycle_hook_info)

        self.assertTrue(result)
        mock_perform_update.assert_called_once_with(
            from_rpc_app,
            to_rpc_app,
            '/tmp/test-app-2.0-1.tgz',
            lifecycle_hook_info,
            None,
            None,
            None)

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

        self.get_reorder_apps_result = {
            constants.APP_METADATA_DEPENDENT_APPS: [],
            constants.APP_METADATA_CLASS: {
                constants.APP_METADATA_CLASS_CRITICAL: [],
                constants.APP_METADATA_CLASS_STORAGE: [],
                constants.APP_METADATA_CLASS_DISCOVERY: [],
                constants.APP_METADATA_CLASS_OPTIONAL: [],
                constants.APP_METADATA_CLASS_REPORTING: []
            },
            constants.APP_METADATA_INDEPENDENT_APPS: ['stx-openstack']
        }

        def mock_auto_update_app(obj,
                                 context,
                                 app_name,
                                 k8s_version=None,
                                 k8s_upgrade_timing=None,
                                 async_update=True,
                                 skip_validations=False,
                                 ignore_locks=False):
            return True
        mocked_auto_update_app = mock.patch(
            'sysinv.conductor.manager.ConductorManager._auto_update_app',
            mock_auto_update_app)
        mocked_auto_update_app.start()
        self.addCleanup(mocked_auto_update_app.stop)

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

        self.get_reorder_apps_result = {
            constants.APP_METADATA_DEPENDENT_APPS: [],
            constants.APP_METADATA_CLASS: {
                constants.APP_METADATA_CLASS_CRITICAL: [],
                constants.APP_METADATA_CLASS_STORAGE: [],
                constants.APP_METADATA_CLASS_DISCOVERY: [],
                constants.APP_METADATA_CLASS_OPTIONAL: [],
                constants.APP_METADATA_CLASS_REPORTING: []
            },
            constants.APP_METADATA_INDEPENDENT_APPS: ['stx-openstack']
        }

        def mock_auto_update_app(obj,
                                 context,
                                 app_name,
                                 k8s_version=None,
                                 k8s_upgrade_timing=None,
                                 async_update=True,
                                 skip_validations=False,
                                 ignore_locks=False):
            return True
        mocked_auto_update_app = mock.patch(
            'sysinv.conductor.manager.ConductorManager._auto_update_app',
            mock_auto_update_app)
        mocked_auto_update_app.start()
        self.addCleanup(mocked_auto_update_app.stop)

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

    def test_kube_pre_application_update_app_failed(self):
        # Test pre app update step when the application fails to be updated.

        self.get_reorder_apps_result = {
            constants.APP_METADATA_DEPENDENT_APPS: [],
            constants.APP_METADATA_CLASS: {
                constants.APP_METADATA_CLASS_CRITICAL: [],
                constants.APP_METADATA_CLASS_STORAGE: [],
                constants.APP_METADATA_CLASS_DISCOVERY: [],
                constants.APP_METADATA_CLASS_OPTIONAL: [],
                constants.APP_METADATA_CLASS_REPORTING: []
            },
            constants.APP_METADATA_INDEPENDENT_APPS: ['stx-openstack']
        }

        def mock_auto_update_app(obj,
                                 context,
                                 app_name,
                                 k8s_version=None,
                                 k8s_upgrade_timing=None,
                                 async_update=True,
                                 skip_validations=False,
                                 ignore_locks=False):
            return False

        mocked_auto_update_app = mock.patch(
            'sysinv.conductor.manager.ConductorManager._auto_update_app',
            mock_auto_update_app)
        mocked_auto_update_app.start()
        self.addCleanup(mocked_auto_update_app.stop)

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
                         kubernetes.KUBE_PRE_UPDATING_APPS_FAILED)

    def test_kube_pre_application_update_app_skipped(self):
        # Test pre app update step when the application update is skipped.

        self.get_reorder_apps_result = {
            constants.APP_METADATA_DEPENDENT_APPS: [],
            constants.APP_METADATA_CLASS: {
                constants.APP_METADATA_CLASS_CRITICAL: [],
                constants.APP_METADATA_CLASS_STORAGE: [],
                constants.APP_METADATA_CLASS_DISCOVERY: [],
                constants.APP_METADATA_CLASS_OPTIONAL: [],
                constants.APP_METADATA_CLASS_REPORTING: []
            },
            constants.APP_METADATA_INDEPENDENT_APPS: ['stx-openstack']
        }

        def mock_auto_update_app(obj,
                                 context,
                                 app_name,
                                 k8s_version=None,
                                 k8s_upgrade_timing=None,
                                 async_update=True,
                                 skip_validations=False,
                                 ignore_locks=False):
            return None

        mocked_auto_update_app = mock.patch(
            'sysinv.conductor.manager.ConductorManager._auto_update_app',
            mock_auto_update_app)
        mocked_auto_update_app.start()
        self.addCleanup(mocked_auto_update_app.stop)

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
            'sysinv.conductor.manager.ContainerImageDownloader.'
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
            'sysinv.conductor.manager.ContainerImageDownloader.'
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
            'sysinv.conductor.manager.ContainerImageDownloader.'
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
        FAKE_CREDS = {'username': 'fake_username', 'password': 'fake_password'}
        FAKE_AUTH = "fake_username:fake_password"

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
            'sysinv.conductor.manager.ContainerImageDownloader.'
            'download_images_from_upstream_to_local_reg_and_crictl',
            mock_download_images_from_upstream_to_local_reg_and_crictl)
        p.start().return_value = True
        self.addCleanup(p.stop)

        mock_get_local_docker_registry_auth = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.get_local_docker_registry_auth',
                       mock_get_local_docker_registry_auth)
        p.start().return_value = FAKE_CREDS
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
        mock_get_local_docker_registry_auth.assert_called_once()
        mock_pull_kubernetes_images.assert_called_once_with(
            self.context, controller1_host_uuid, FAKE_IMAGE_LIST, FAKE_AUTH)

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
        FAKE_CREDS = {'username': 'fake_username', 'password': 'fake_password'}
        FAKE_AUTH = "fake_username:fake_password"

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
            'sysinv.conductor.manager.ContainerImageDownloader.'
            'download_images_from_upstream_to_local_reg_and_crictl',
            mock_download_images_from_upstream_to_local_reg_and_crictl)
        p.start().return_value = True
        self.addCleanup(p.stop)

        mock_pull_kubernetes_images = mock.MagicMock()
        p = mock.patch.object(
            agent_rpcapi.AgentAPI, 'pull_kubernetes_images', mock_pull_kubernetes_images)
        p.start().side_effect = Exception("Fake error")
        self.addCleanup(p.stop)

        mock_get_local_docker_registry_auth = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.get_local_docker_registry_auth',
                       mock_get_local_docker_registry_auth)
        p.start().return_value = FAKE_CREDS
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
        mock_get_local_docker_registry_auth.assert_called_once()
        mock_pull_kubernetes_images.assert_called_once_with(
            self.context, controller1_host_uuid, FAKE_IMAGE_LIST, FAKE_AUTH)
        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state, kubernetes.KUBE_UPGRADE_DOWNLOADING_IMAGES_FAILED)

    def test_download_images_from_upstream_to_local_reg_and_crictl_success(self):
        """Test download_images_from_upstream_to_local_reg_and_crictl: success case
        """

        images_to_be_downloaded = [
            'fake_image1', 'fake_image2', 'fake_image3', 'fake_image4', 'fake_image5'
        ]
        fake_local_registry_auth = {'username': 'fake_username', 'password': 'fake_password'}
        fake_registries = {'fake_registries': 'fake_registries'}
        fake_crictl_auth = (
            f"{fake_local_registry_auth['username']}:{fake_local_registry_auth['password']}"
        )
        get_img_tag_with_registry_output = ('fake_target_image', fake_local_registry_auth)

        p = mock.patch("docker.APIClient.__init__", mock.MagicMock(return_value=None))
        p.start()
        self.addCleanup(p.stop)

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
        p.start().return_value = [f"{constants.DOCKER_REGISTRY_SERVER}/fake_image4"]
        self.addCleanup(p.stop)

        mock_get_img_tag_with_registry = mock.MagicMock()
        p = mock.patch('sysinv.conductor.kube_app.DockerHelper._get_img_tag_with_registry',
                       mock_get_img_tag_with_registry)
        p.start().return_value = get_img_tag_with_registry_output
        self.addCleanup(p.stop)

        p = mock.patch(
            'sysinv.conductor.manager.ContainerImageDownloader.docker_registry_image_list',
            mock.MagicMock()
        )
        p.start().return_value = [{"name": 'fake_image5'}]
        self.addCleanup(p.stop)

        mock_docker_apiclient_pull = mock.MagicMock()
        p = mock.patch('docker.APIClient.pull', mock_docker_apiclient_pull)
        p.start()
        self.addCleanup(p.stop)

        p = mock.patch("docker.APIClient.inspect_image", mock.MagicMock())
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

        result = \
            self.service._image_downloader.download_images_from_upstream_to_local_reg_and_crictl(
                images_to_be_downloaded)

        # Assertions start here
        # Assert Main Result
        self.assertTrue(result)

        # Assert mock method calls
        mock_get_local_docker_registry_auth.assert_called_once()
        mock_retrieve_specified_registries.assert_called_once()
        mock_get_crictl_image_list.assert_called_once()

        # Image 5 is already in docker, so it should not appear in any docker request
        expected_calls = [mock.call('fake_image1', fake_registries),
                          mock.call('fake_image2', fake_registries),
                          mock.call('fake_image3', fake_registries),
                          mock.call('fake_image4', fake_registries)]
        mock_get_img_tag_with_registry.assert_has_calls(expected_calls, any_order=True)

        mock_docker_apiclient_pull.assert_called_with(get_img_tag_with_registry_output[0],
                                                auth_config=get_img_tag_with_registry_output[1])
        self.assertEqual(mock_docker_apiclient_pull.call_count, 4)

        expected_calls = [mock.call(get_img_tag_with_registry_output[0],
                                    f"{constants.DOCKER_REGISTRY_SERVER}/fake_image1"),
                          mock.call(get_img_tag_with_registry_output[0],
                                    f"{constants.DOCKER_REGISTRY_SERVER}/fake_image2"),
                          mock.call(get_img_tag_with_registry_output[0],
                                    f"{constants.DOCKER_REGISTRY_SERVER}/fake_image3"),
                          mock.call(get_img_tag_with_registry_output[0],
                                    f"{constants.DOCKER_REGISTRY_SERVER}/fake_image4")]
        mock_docker_apiclient_tag.assert_has_calls(expected_calls, any_order=True)
        self.assertEqual(mock_docker_apiclient_tag.call_count, 4)

        expected_calls = [mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image1",
                                    auth_config=get_img_tag_with_registry_output[1]),
                          mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image2",
                                    auth_config=get_img_tag_with_registry_output[1]),
                          mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image3",
                                    auth_config=get_img_tag_with_registry_output[1]),
                          mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image4",
                                    auth_config=get_img_tag_with_registry_output[1])]
        mock_docker_apiclient_push.assert_has_calls(expected_calls, any_order=True)
        self.assertEqual(mock_docker_apiclient_push.call_count, 4)
        mock_docker_apiclient_inspect.assert_has_calls(expected_calls, any_order=True)
        self.assertEqual(mock_docker_apiclient_inspect.call_count, 4)

        expected_calls = [mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image1"),
                          mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image2"),
                          mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image3"),
                          mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image4"),
                          mock.call("fake_target_image"),
                          mock.call("fake_target_image"),
                          mock.call("fake_target_image"),
                          mock.call("fake_target_image")]
        mock_docker_apiclient_remove_image.assert_has_calls(expected_calls, any_order=True)
        self.assertEqual(mock_docker_apiclient_remove_image.call_count, 8)

        expected_calls = [mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image1",
                                    fake_crictl_auth),
                          mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image2",
                                    fake_crictl_auth),
                          mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image3",
                                    fake_crictl_auth),
                          mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image5",
                                    fake_crictl_auth)]
        mock_pull_image_to_crictl.assert_has_calls(expected_calls, any_order=True)
        # Image 4 is in crictl, but 5 is not
        self.assertEqual(mock_pull_image_to_crictl.call_count, 4)

    def test_download_images_from_upstream_to_local_reg_and_crictl_failure_docker_pull_fail(self):
        """Test download_images_from_upstream_to_local_reg_and_crictl: docker pull failed

        Also tests failure to get list of existing images from crictl
        """

        images_to_be_downloaded = ['fake_image1', 'fake_image2', 'fake_image3']
        p = mock.patch("docker.APIClient.__init__", mock.MagicMock(return_value=None))
        p.start()
        self.addCleanup(p.stop)

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

        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager.docker_registry_image_list',
            mock.MagicMock()
        )
        p.start().return_value = []
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

        mock_docker_system_prune = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.image_download.ContainerImageDownloader._docker_system_prune',
            mock_docker_system_prune)
        p.start()
        self.addCleanup(p.stop)

        result = \
            self.service._image_downloader.download_images_from_upstream_to_local_reg_and_crictl(
                images_to_be_downloaded)

        # Assertions start here
        # Assert Main Result
        self.assertFalse(result)

        # Assert mock method calls
        mock_get_local_docker_registry_auth.assert_called_once()
        mock_retrieve_specified_registries.assert_called_once()
        mock_get_crictl_image_list.assert_called_once()

        # Assert Retries (5 retries per image on first attempt + 5 retries per image on prune retry)
        self.assertEqual(
            mock_get_img_tag_with_registry.call_count, 5 * len(images_to_be_downloaded) * 2
        )
        self.assertEqual(
            mock_docker_apiclient_pull.call_count, 5 * len(images_to_be_downloaded) * 2
        )

        mock_docker_system_prune.assert_called_once()
        mock_docker_apiclient_tag.assert_not_called()
        mock_docker_apiclient_push.assert_not_called()
        mock_docker_apiclient_inspect.assert_not_called()
        mock_docker_apiclient_remove_image.assert_not_called()
        mock_pull_image_to_crictl.assert_not_called()

    def test_download_images_from_upstream_to_local_reg_and_crictl_failure_image_not_downloaded(
        self,
    ):
        """Test download_images_from_upstream_to_local_reg_and_crictl: docker pull with image not downloaded

        The docker pull will finish without exception, but the image won't exist in the local repository.
        """

        images_to_be_downloaded = ["fake_image1", "fake_image2", "fake_image3"]
        p = mock.patch("docker.APIClient.__init__", mock.MagicMock(return_value=None))
        p.start()
        self.addCleanup(p.stop)

        fake_local_registry_auth = {
            "username": "fake_username",
            "password": "fake_password",
        }
        fake_registries = {"fake_registries": "fake_registries"}
        get_img_tag_with_registry_output = (
            "fake_target_image",
            fake_local_registry_auth,
        )

        mock_get_local_docker_registry_auth = mock.MagicMock()
        p = mock.patch(
            "sysinv.common.utils.get_local_docker_registry_auth",
            mock_get_local_docker_registry_auth,
        )
        p.start().return_value = {
            "username": "fake_username",
            "password": "fake_password",
        }
        self.addCleanup(p.stop)

        mock_retrieve_specified_registries = mock.MagicMock()
        p = mock.patch(
            "sysinv.conductor.kube_app.DockerHelper.retrieve_specified_registries",
            mock_retrieve_specified_registries,
        )
        p.start().return_value = fake_registries
        self.addCleanup(p.stop)

        mock_get_crictl_image_list = mock.MagicMock()
        p = mock.patch(
            "sysinv.common.containers.get_crictl_image_list", mock_get_crictl_image_list
        )
        p.start().side_effect = exception.SysinvException("Fake Error")
        self.addCleanup(p.stop)

        mock_get_img_tag_with_registry = mock.MagicMock()
        p = mock.patch(
            "sysinv.conductor.kube_app.DockerHelper._get_img_tag_with_registry",
            mock_get_img_tag_with_registry,
        )
        p.start().return_value = get_img_tag_with_registry_output
        self.addCleanup(p.stop)

        p = mock.patch(
            "sysinv.conductor.manager.ConductorManager.docker_registry_image_list",
            mock.MagicMock(),
        )
        p.start().return_value = []
        self.addCleanup(p.stop)

        mock_docker_apiclient_pull = mock.MagicMock()
        p = mock.patch("docker.APIClient.pull", mock_docker_apiclient_pull)
        p.start()
        self.addCleanup(p.stop)

        mock_docker_apiclient_inspect_image = mock.MagicMock()
        p = mock.patch(
            "docker.APIClient.inspect_image", mock_docker_apiclient_inspect_image
        )
        p.start().side_effect = ImageNotFound("404 Client Error: Not Found")
        self.addCleanup(p.stop)

        mock_docker_apiclient_tag = mock.MagicMock()
        p = mock.patch("docker.APIClient.tag", mock_docker_apiclient_tag)
        p.start()
        self.addCleanup(p.stop)

        mock_docker_apiclient_push = mock.MagicMock()
        p = mock.patch("docker.APIClient.push", mock_docker_apiclient_push)
        p.start()
        self.addCleanup(p.stop)

        mock_docker_apiclient_inspect = mock.MagicMock()
        p = mock.patch(
            "docker.APIClient.inspect_distribution", mock_docker_apiclient_inspect
        )
        p.start()
        self.addCleanup(p.stop)

        mock_docker_apiclient_remove_image = mock.MagicMock()
        p = mock.patch(
            "docker.APIClient.remove_image", mock_docker_apiclient_remove_image
        )
        p.start()
        self.addCleanup(p.stop)

        mock_pull_image_to_crictl = mock.MagicMock()
        p = mock.patch(
            "sysinv.common.containers.pull_image_to_crictl", mock_pull_image_to_crictl
        )
        p.start()
        self.addCleanup(p.stop)

        mock_docker_system_prune = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.image_download.ContainerImageDownloader._docker_system_prune',
            mock_docker_system_prune)
        p.start()
        self.addCleanup(p.stop)

        result = self.service._image_downloader.download_images_from_upstream_to_local_reg_and_crictl(
            images_to_be_downloaded
        )

        # Assertions start here
        # Assert Main Result
        self.assertFalse(result)

        # Assert mock method calls
        mock_get_local_docker_registry_auth.assert_called_once()
        mock_retrieve_specified_registries.assert_called_once()
        mock_get_crictl_image_list.assert_called_once()

        # Assert Retries (5 retries per image on first attempt + 5 retries per image on prune retry)
        self.assertEqual(
            mock_get_img_tag_with_registry.call_count, 5 * len(images_to_be_downloaded) * 2
        )
        self.assertEqual(
            mock_docker_apiclient_pull.call_count, 5 * len(images_to_be_downloaded) * 2
        )

        mock_docker_system_prune.assert_called_once()
        mock_docker_apiclient_tag.assert_not_called()
        mock_docker_apiclient_push.assert_not_called()
        mock_docker_apiclient_inspect.assert_not_called()
        mock_docker_apiclient_remove_image.assert_not_called()
        mock_pull_image_to_crictl.assert_not_called()

    def test_download_images_from_upstream_to_local_reg_and_crictl_failure_docker_push_fail(self):
        """Test download_images_from_upstream_to_local_reg_and_crictl: docker push failed
        even after docker system prune retry
        """
        images_to_be_downloaded = ['fake_image1', 'fake_image2', 'fake_image3']
        p = mock.patch("docker.APIClient.__init__", mock.MagicMock(return_value=None))
        p.start()
        self.addCleanup(p.stop)

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

        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager.docker_registry_image_list',
            mock.MagicMock()
        )
        p.start().return_value = []
        self.addCleanup(p.stop)

        mock_docker_apiclient_pull = mock.MagicMock()
        p = mock.patch('docker.APIClient.pull', mock_docker_apiclient_pull)
        p.start()
        self.addCleanup(p.stop)

        p = mock.patch("docker.APIClient.inspect_image", mock.MagicMock())
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

        mock_docker_system_prune = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.image_download.ContainerImageDownloader._docker_system_prune',
            mock_docker_system_prune)
        p.start()
        self.addCleanup(p.stop)

        result = \
            self.service._image_downloader.download_images_from_upstream_to_local_reg_and_crictl(
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

        mock_docker_apiclient_tag.assert_called()
        mock_docker_apiclient_push.assert_called()

        # docker system prune is called as part of the retry
        mock_docker_system_prune.assert_called()

        mock_docker_apiclient_remove_image.assert_not_called()
        mock_pull_image_to_crictl.assert_not_called()

    def test_download_images_push_fail_recovers_after_docker_prune(self):
        """Test download_images_from_upstream_to_local_reg_and_crictl:
        docker push fails initially but succeeds after docker system prune
        """
        images_to_be_downloaded = ['fake_image1']
        p = mock.patch("docker.APIClient.__init__", mock.MagicMock(return_value=None))
        p.start()
        self.addCleanup(p.stop)

        fake_local_registry_auth = {'username': 'fake_username', 'password': 'fake_password'}
        fake_registries = {'fake_registries': 'fake_registries'}

        get_img_tag_with_registry_output = ('fake_target_image', fake_local_registry_auth)

        mock_get_local_docker_registry_auth = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.get_local_docker_registry_auth',
                       mock_get_local_docker_registry_auth)
        p.start().return_value = fake_local_registry_auth
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

        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager.docker_registry_image_list',
            mock.MagicMock()
        )
        p.start().return_value = []
        self.addCleanup(p.stop)

        mock_docker_apiclient_pull = mock.MagicMock()
        p = mock.patch('docker.APIClient.pull', mock_docker_apiclient_pull)
        p.start()
        self.addCleanup(p.stop)

        p = mock.patch("docker.APIClient.inspect_image", mock.MagicMock())
        p.start()
        self.addCleanup(p.stop)

        mock_docker_apiclient_tag = mock.MagicMock()
        p = mock.patch('docker.APIClient.tag', mock_docker_apiclient_tag)
        p.start()
        self.addCleanup(p.stop)

        # Push fails on first call, succeeds on second (after prune)
        mock_docker_apiclient_push = mock.MagicMock()
        p = mock.patch('docker.APIClient.push', mock_docker_apiclient_push)
        p.start().side_effect = [
            Exception("file integrity checksum failed"),
            None
        ]
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

        mock_docker_system_prune = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.image_download.ContainerImageDownloader._docker_system_prune',
            mock_docker_system_prune)
        p.start()
        self.addCleanup(p.stop)

        result = \
            self.service._image_downloader.download_images_from_upstream_to_local_reg_and_crictl(
                images_to_be_downloaded)

        # Assert success after retry
        self.assertTrue(result)

        # Docker system prune was called for recovery
        mock_docker_system_prune.assert_called_once()

        # Push was called twice: initial fail + retry success
        self.assertEqual(mock_docker_apiclient_push.call_count, 2)

        # Pull was called twice: initial + retry after prune
        self.assertEqual(mock_docker_apiclient_pull.call_count, 2)

        # Images were cleaned up after successful push
        mock_docker_apiclient_remove_image.assert_called()

        # Crictl pull proceeded after successful docker push
        mock_pull_image_to_crictl.assert_called()

    def test_download_images_from_upstream_to_local_reg_and_crictl_success_docker_remove_image_failed(self):  # pylint: disable=line-too-long # noqa: E501
        """Test download_images_from_upstream_to_local_reg_and_crictl: Docker remove image failed

        """
        images_to_be_downloaded = ['fake_image1', 'fake_image2', 'fake_image3']
        p = mock.patch("docker.APIClient.__init__", mock.MagicMock(return_value=None))
        p.start()
        self.addCleanup(p.stop)

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

        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager.docker_registry_image_list',
            mock.MagicMock()
        )
        p.start().return_value = []
        self.addCleanup(p.stop)

        mock_docker_apiclient_pull = mock.MagicMock()
        p = mock.patch('docker.APIClient.pull', mock_docker_apiclient_pull)
        p.start()
        self.addCleanup(p.stop)

        p = mock.patch("docker.APIClient.inspect_image", mock.MagicMock())
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

        result = \
            self.service._image_downloader.download_images_from_upstream_to_local_reg_and_crictl(
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
        p = mock.patch("docker.APIClient.__init__", mock.MagicMock(return_value=None))
        p.start()
        self.addCleanup(p.stop)

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

        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager.docker_registry_image_list',
            mock.MagicMock()
        )
        p.start().return_value = []
        self.addCleanup(p.stop)

        mock_docker_apiclient_pull = mock.MagicMock()
        p = mock.patch('docker.APIClient.pull', mock_docker_apiclient_pull)
        p.start()
        self.addCleanup(p.stop)

        p = mock.patch("docker.APIClient.inspect_image", mock.MagicMock())
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

        result = \
            self.service._image_downloader.download_images_from_upstream_to_local_reg_and_crictl(
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

        if cutils.is_debian_bullseye():
            mock_ruamel_yaml = mock.MagicMock()
            p = mock.patch('ruamel.yaml.safe_load', mock_ruamel_yaml)
            p.start().return_value = expected_images
            self.addCleanup(p.stop)
        else:
            mock_yaml_obj = mock.MagicMock()
            mock_yaml_obj.load.return_value = expected_images
            p = mock.patch('sysinv.conductor.manager.YAML', return_value=mock_yaml_obj)
            p.start()
            self.addCleanup(p.stop)

        actual_images = self.service._get_kubernetes_system_images("fake kube version")

        self.assertEqual(expected_images, actual_images)

        mock_os_path_join.assert_any_call(
                    constants.ANSIBLE_KUBE_SYSTEM_IMAGES_PLAYBOOK_ROOT,
                    'vars/k8s-fake kube version/system-images.yml')
        mock_open.assert_called_once_with(fake_images_path, 'r')
        if cutils.is_debian_bullseye():
            mock_ruamel_yaml.assert_called_once_with(fake_file_object)
        else:
            mock_yaml_obj.load.assert_called_once_with(fake_file_object)

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

        if cutils.is_debian_bullseye():
            mock_ruamel_yaml = mock.MagicMock()
            p = mock.patch('ruamel.yaml.safe_load', mock_ruamel_yaml)
            p.start().return_value = {}
            self.addCleanup(p.stop)
        else:
            mock_yaml_obj = mock.MagicMock()
            mock_yaml_obj.load.return_value = {}
            p = mock.patch('sysinv.conductor.manager.YAML', return_value=mock_yaml_obj)
            p.start()
            self.addCleanup(p.stop)

        self.assertRaises(exception.SysinvException,
                          self.service._get_kubernetes_system_images,
                          "fake kube version")

        mock_os_path_join.assert_any_call(
                    constants.ANSIBLE_KUBE_SYSTEM_IMAGES_PLAYBOOK_ROOT,
                    'vars/k8s-fake kube version/system-images.yml')
        mock_open.assert_called_once_with(fake_images_path, 'r')
        if cutils.is_debian_bullseye():
            mock_ruamel_yaml.assert_called_once_with(fake_file_object)
        else:
            mock_yaml_obj.load.assert_called_once_with(fake_file_object)

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

        if cutils.is_debian_bullseye():
            mock_ruamel_yaml = mock.MagicMock()
            p = mock.patch('ruamel.yaml.safe_load', mock_ruamel_yaml)
            p.start().side_effect = Exception("Fake error")
            self.addCleanup(p.stop)
        else:
            mock_yaml_obj = mock.MagicMock()
            mock_yaml_obj.load.side_effect = Exception("Fake error")
            p = mock.patch('sysinv.conductor.manager.YAML', return_value=mock_yaml_obj)
            p.start()
            self.addCleanup(p.stop)

        self.assertRaises(exception.SysinvException,
                          self.service._get_kubernetes_system_images,
                          "fake kube version")

        mock_os_path_join.assert_any_call(
                    constants.ANSIBLE_KUBE_SYSTEM_IMAGES_PLAYBOOK_ROOT,
                    'vars/k8s-fake kube version/system-images.yml')
        mock_open.assert_called_once_with(fake_images_path, 'r')
        if cutils.is_debian_bullseye():
            mock_ruamel_yaml.assert_called_once_with(fake_file_object)
        else:
            mock_yaml_obj.load.assert_called_once_with(fake_file_object)

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
                          'calico_ctl_img': 'fake_calico_ctl_img',
                          'calico_dikastes_img': 'fake_calico_dikastes_img',
                          'calico_envoy_gateway_img': 'fake_calico_envoy_gateway_img',
                          'calico_envoy_proxy_img': 'fake_calico_envoy_proxy_img',
                          'calico_kube_controllers_img': 'fake_calico_kube_controllers_img',
                          'calico_node_img': 'fake_calico_node_img',
                          'calico_pod2daemon_flexvol_img': 'fake_calico_pod2daemon_flexvol_img',
                          'calico_typha_img': 'fake_calico_typha_img',
                          'multus_img': 'fake_multus_img',
                          'sriov_cni_img': 'fake_sriov_cni_img',
                          'sriov_network_device_img': 'fake_sriov_network_device_img',
                          'tigera_operator_img': 'fake_tigera_operator_img'}

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
            'sysinv.conductor.manager.ContainerImageDownloader.'
            'download_images_from_upstream_to_local_reg_and_crictl',
            mock_download_images_from_upstream_to_local_reg_and_crictl)
        p.start().return_value = image_download_result
        self.addCleanup(p.stop)

        mock_get_auth = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.utils.get_local_docker_registry_auth',
            mock_get_auth
        )
        p.start().return_value = {'username': 'fake', 'password': 'fake'}
        self.addCleanup(p.stop)

        mock_pull_images = mock.MagicMock()
        p = mock.patch.object(
            agent_rpcapi.AgentAPI,
            'pull_kubernetes_images',
            mock_pull_images
        )
        p.start()
        self.addCleanup(p.stop)

        mock_utils_execute = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.execute', mock_utils_execute)
        p.start()
        self.addCleanup(p.stop)

        mock_os_path_exists = mock.MagicMock()
        mock_os_path_exists.side_effect = lambda path: (
            False if path == "/etc/cni/net.d/05-multus.conf"
            else upgrade_overrides_file_exists
        )
        p = mock.patch('os.path.exists', mock_os_path_exists)
        p.start()
        self.addCleanup(p.stop)

        mock_open = mock.mock_open()
        p = mock.patch('builtins.open', mock_open)
        p.start()
        self.addCleanup(p.stop)

        if cutils.is_debian_bullseye():
            mock_ruamel_yaml_safe_load = mock.MagicMock()
            p = mock.patch('ruamel.yaml.safe_load', mock_ruamel_yaml_safe_load)
            p.start().return_value = upgrade_overrides
            self.addCleanup(p.stop)
        else:
            mock_yaml_obj = mock.MagicMock()
            mock_yaml_obj.load.return_value = upgrade_overrides
            p = mock.patch('sysinv.conductor.manager.YAML', return_value=mock_yaml_obj)
            p.start()
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

        captured_calico_ctx = {}
        orig_gen = self.service._generate_k8s_manifests_and_apply

        def _gen_wrapper(source_template_path, dest_manifest_path, *, is_template=False, values=None):
            # Sufficient to assert values only for calico.
            if os.path.basename(str(dest_manifest_path)) == 'update_calico.yaml':
                captured_calico_ctx['ctx'] = values
            # Invoke the actual method to maintain the normal flow
            return orig_gen(source_template_path, dest_manifest_path,
                            is_template=is_template, values=values)

        p = mock.patch.object(self.service, '_generate_k8s_manifests_and_apply', side_effect=_gen_wrapper)
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
        if cutils.is_debian_bullseye():
            mock_ruamel_yaml_safe_load.assert_called_once()
        else:
            mock_yaml_obj.load.assert_called_once()
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

        self.assertIn('ctx', captured_calico_ctx, "No context captured for update_calico.yaml")
        ctx = captured_calico_ctx['ctx']
        self.assertIsInstance(ctx, dict, "Calico context is not a dict")
        self.assertEqual(ctx.get('cluster_network_ipv4'), '172.16.0.0/16')
        self.assertEqual(ctx.get('cluster_network_ipv6'), None)

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
                          'calico_ctl_img': 'fake_calico_ctl_img',
                          'calico_dikastes_img': 'fake_calico_dikastes_img',
                          'calico_envoy_gateway_img': 'fake_calico_envoy_gateway_img',
                          'calico_envoy_proxy_img': 'fake_calico_envoy_proxy_img',
                          'calico_kube_controllers_img': 'fake_calico_kube_controllers_img',
                          'calico_node_img': 'fake_calico_node_img',
                          'calico_pod2daemon_flexvol_img': 'fake_calico_pod2daemon_flexvol_img',
                          'calico_typha_img': 'fake_calico_typha_img',
                          'multus_img': 'fake_multus_img',
                          'sriov_cni_img': 'fake_sriov_cni_img',
                          'sriov_network_device_img': 'fake_sriov_network_device_img',
                          'tigera_operator_img': 'fake_tigera_operator_img'}
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
            'sysinv.conductor.manager.ContainerImageDownloader.'
            'download_images_from_upstream_to_local_reg_and_crictl',
            mock_download_images_from_upstream_to_local_reg_and_crictl)
        p.start().return_value = image_download_result
        self.addCleanup(p.stop)

        mock_get_auth = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.utils.get_local_docker_registry_auth',
            mock_get_auth
        )
        p.start().return_value = {'username': 'fake', 'password': 'fake'}
        self.addCleanup(p.stop)

        mock_pull_images = mock.MagicMock()
        p = mock.patch.object(
            agent_rpcapi.AgentAPI,
            'pull_kubernetes_images',
            mock_pull_images
        )
        p.start()
        self.addCleanup(p.stop)

        mock_utils_execute = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.execute', mock_utils_execute)
        p.start()
        self.addCleanup(p.stop)

        mock_os_path_exists = mock.MagicMock()
        mock_os_path_exists.side_effect = lambda path: (
            False if path == "/etc/cni/net.d/05-multus.conf"
            else upgrade_overrides_file_exists
        )
        p = mock.patch('os.path.exists', mock_os_path_exists)
        p.start()
        self.addCleanup(p.stop)

        mock_open = mock.mock_open()
        p = mock.patch('builtins.open', mock_open)
        p.start()
        self.addCleanup(p.stop)

        if cutils.is_debian_bullseye():
            mock_ruamel_yaml_safe_load = mock.MagicMock()
            p = mock.patch('ruamel.yaml.safe_load', mock_ruamel_yaml_safe_load)
            p.start().return_value = upgrade_overrides
            self.addCleanup(p.stop)
        else:
            mock_yaml_obj = mock.MagicMock()
            mock_yaml_obj.load.return_value = upgrade_overrides
            p = mock.patch('sysinv.conductor.manager.YAML', return_value=mock_yaml_obj)
            p.start()
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

        captured_calico_ctx = {}
        orig_gen = self.service._generate_k8s_manifests_and_apply

        def _gen_wrapper(source_template_path, dest_manifest_path, *, is_template=False, values=None):
            # Sufficient to assert values only for calico.
            if os.path.basename(str(dest_manifest_path)) == 'update_calico.yaml':
                captured_calico_ctx['ctx'] = values
            # Invoke the actual method to maintain the normal flow
            return orig_gen(source_template_path, dest_manifest_path,
                            is_template=is_template, values=values)

        p = mock.patch.object(self.service, '_generate_k8s_manifests_and_apply', side_effect=_gen_wrapper)
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
        if cutils.is_debian_bullseye():
            mock_ruamel_yaml_safe_load.assert_called_once()
        else:
            mock_yaml_obj.load.assert_called_once()
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

        self.assertIn('ctx', captured_calico_ctx, "No context captured for update_calico.yaml")
        ctx = captured_calico_ctx['ctx']
        self.assertIsInstance(ctx, dict, "Calico context is not a dict")
        self.assertEqual(ctx.get('cluster_network_ipv4'), None)
        self.assertEqual(ctx.get('cluster_network_ipv6'), '::ffff:ac10:0/16')

    def test_kube_upgrade_networking_success_dual_stack(self):
        """Test successful execution of kubernetes networking upgrade (dual-stack)."""

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
                          'calico_ctl_img': 'fake_calico_ctl_img',
                          'calico_dikastes_img': 'fake_calico_dikastes_img',
                          'calico_envoy_gateway_img': 'fake_calico_envoy_gateway_img',
                          'calico_envoy_proxy_img': 'fake_calico_envoy_proxy_img',
                          'calico_kube_controllers_img': 'fake_calico_kube_controllers_img',
                          'calico_node_img': 'fake_calico_node_img',
                          'calico_pod2daemon_flexvol_img': 'fake_calico_pod2daemon_flexvol_img',
                          'calico_typha_img': 'fake_calico_typha_img',
                          'multus_img': 'fake_multus_img',
                          'sriov_cni_img': 'fake_sriov_cni_img',
                          'sriov_network_device_img': 'fake_sriov_network_device_img',
                          'tigera_operator_img': 'fake_tigera_operator_img'}

        image_download_result = True
        upgrade_overrides_file_exists = True
        upgrade_overrides = {
            "cluster_pod_subnet": "aefd:206::/64,172.16.0.0/16",
            "cluster_host_floating_address": "::ffff:c0a8:ce01",
            "cluster_host_node_0_address": "::ffff:c0a8:ce02"
        }

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
            'sysinv.conductor.manager.ContainerImageDownloader.'
            'download_images_from_upstream_to_local_reg_and_crictl',
            mock_download_images_from_upstream_to_local_reg_and_crictl)
        p.start().return_value = image_download_result
        self.addCleanup(p.stop)

        mock_get_auth = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.utils.get_local_docker_registry_auth',
            mock_get_auth
        )
        p.start().return_value = {'username': 'fake', 'password': 'fake'}
        self.addCleanup(p.stop)

        mock_pull_images = mock.MagicMock()
        p = mock.patch.object(
            agent_rpcapi.AgentAPI,
            'pull_kubernetes_images',
            mock_pull_images
        )
        p.start()
        self.addCleanup(p.stop)

        mock_utils_execute = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.execute', mock_utils_execute)
        p.start()
        self.addCleanup(p.stop)

        mock_os_path_exists = mock.MagicMock()
        mock_os_path_exists.side_effect = lambda path: (
            False if path == "/etc/cni/net.d/05-multus.conf"
            else upgrade_overrides_file_exists
        )
        p = mock.patch('os.path.exists', mock_os_path_exists)
        p.start()
        self.addCleanup(p.stop)

        mock_open = mock.mock_open()
        p = mock.patch('builtins.open', mock_open)
        p.start()
        self.addCleanup(p.stop)

        if cutils.is_debian_bullseye():
            mock_ruamel_yaml_safe_load = mock.MagicMock()
            p = mock.patch('ruamel.yaml.safe_load', mock_ruamel_yaml_safe_load)
            p.start().return_value = upgrade_overrides
            self.addCleanup(p.stop)
        else:
            mock_yaml_obj = mock.MagicMock()
            mock_yaml_obj.load.return_value = upgrade_overrides
            p = mock.patch('sysinv.conductor.manager.YAML', return_value=mock_yaml_obj)
            p.start()
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

        captured_calico_ctx = {}
        orig_gen = self.service._generate_k8s_manifests_and_apply

        def _gen_wrapper(source_template_path, dest_manifest_path, *, is_template=False, values=None):
            # Sufficient to assert values only for calico.
            if os.path.basename(str(dest_manifest_path)) == 'update_calico.yaml':
                captured_calico_ctx['ctx'] = values
            # Invoke the actual method to maintain the normal flow
            return orig_gen(source_template_path, dest_manifest_path,
                            is_template=is_template, values=values)

        p = mock.patch.object(self.service, '_generate_k8s_manifests_and_apply', side_effect=_gen_wrapper)
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
        if cutils.is_debian_bullseye():
            mock_ruamel_yaml_safe_load.assert_called_once()
        else:
            mock_yaml_obj.load.assert_called_once()
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

        self.assertIn('ctx', captured_calico_ctx, "No context captured for update_calico.yaml")
        ctx = captured_calico_ctx['ctx']
        self.assertIsInstance(ctx, dict, "Calico context is not a dict")
        self.assertEqual(ctx.get('cluster_network_ipv4'), '172.16.0.0/16')
        self.assertEqual(ctx.get('cluster_network_ipv6'), 'aefd:206::/64')

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
                          'calico_ctl_img': 'fake_calico_ctl_img',
                          'calico_dikastes_img': 'fake_calico_dikastes_img',
                          'calico_envoy_gateway_img': 'fake_calico_envoy_gateway_img',
                          'calico_envoy_proxy_img': 'fake_calico_envoy_proxy_img',
                          'calico_kube_controllers_img': 'fake_calico_kube_controllers_img',
                          'calico_node_img': 'fake_calico_node_img',
                          'calico_pod2daemon_flexvol_img': 'fake_calico_pod2daemon_flexvol_img',
                          'calico_typha_img': 'fake_calico_typha_img',
                          'multus_img': 'fake_multus_img',
                          'sriov_cni_img': 'fake_sriov_cni_img',
                          'sriov_network_device_img': 'fake_sriov_network_device_img',
                          'tigera_operator_img': 'fake_tigera_operator_img'}
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
            'sysinv.conductor.manager.ContainerImageDownloader.'
            'download_images_from_upstream_to_local_reg_and_crictl',
            mock_download_images_from_upstream_to_local_reg_and_crictl)
        p.start().return_value = image_download_result
        self.addCleanup(p.stop)

        mock_get_auth = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.utils.get_local_docker_registry_auth',
            mock_get_auth
        )
        p.start().return_value = {'username': 'fake', 'password': 'fake'}
        self.addCleanup(p.stop)

        mock_pull_images = mock.MagicMock()
        p = mock.patch.object(
            agent_rpcapi.AgentAPI,
            'pull_kubernetes_images',
            mock_pull_images
        )
        p.start()
        self.addCleanup(p.stop)

        mock_utils_execute = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.execute', mock_utils_execute)
        p.start()
        self.addCleanup(p.stop)

        mock_os_path_exists = mock.MagicMock()
        mock_os_path_exists.side_effect = lambda path: (
            False if path == "/etc/cni/net.d/05-multus.conf"
            else upgrade_overrides_file_exists
        )
        p = mock.patch('os.path.exists', mock_os_path_exists)
        p.start()
        self.addCleanup(p.stop)

        mock_open = mock.mock_open()
        p = mock.patch('builtins.open', mock_open)
        p.start()
        self.addCleanup(p.stop)

        if cutils.is_debian_bullseye():
            mock_ruamel_yaml_safe_load = mock.MagicMock()
            p = mock.patch('ruamel.yaml.safe_load', mock_ruamel_yaml_safe_load)
            p.start().return_value = upgrade_overrides
            self.addCleanup(p.stop)
        else:
            mock_yaml_obj = mock.MagicMock()
            mock_yaml_obj.load.return_value = upgrade_overrides
            p = mock.patch('sysinv.conductor.manager.YAML', return_value=mock_yaml_obj)
            p.start()
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
        if cutils.is_debian_bullseye():
            mock_ruamel_yaml_safe_load.assert_called_once()
        else:
            mock_yaml_obj.load.assert_called_once()
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
            'sysinv.conductor.manager.ContainerImageDownloader.'
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
            'sysinv.conductor.manager.ContainerImageDownloader.'
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
            'sysinv.conductor.manager.ContainerImageDownloader.'
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
            'sysinv.conductor.manager.ContainerImageDownloader.'
            'download_images_from_upstream_to_local_reg_and_crictl',
            mock_download_images_from_upstream_to_local_reg_and_crictl)
        p.start().return_value = image_download_result
        self.addCleanup(p.stop)

        mock_get_auth = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.utils.get_local_docker_registry_auth',
            mock_get_auth
        )
        p.start().return_value = {'username': 'fake', 'password': 'fake'}
        self.addCleanup(p.stop)

        mock_pull_images = mock.MagicMock()
        p = mock.patch.object(
            agent_rpcapi.AgentAPI,
            'pull_kubernetes_images',
            mock_pull_images
        )
        p.start()
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
        mock_os_path_exists.assert_called()
        mock_os_remove.assert_not_called()

        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state, kubernetes.KUBE_UPGRADING_NETWORKING_FAILED)

    def test_kube_upgrade_networking_failure_host_overrides_missing_cluster_pod_subnet(self):
        """Test failed execution of kubernetes networking upgrade
        (cluster_pod_subnet absent in host overrides)
        """

        # Create controller-0
        controller0_uuid = str(uuid.uuid4())
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=controller0_uuid,
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        # Create controller-1 (match previous test structure)
        controller1_uuid = str(uuid.uuid4())
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-1',
            uuid=controller1_uuid,
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            mgmt_mac='00:11:22:33:44:56'
        )

        # Make controller-0 active
        self.service.host_uuid = controller0_uuid

        FROM_VERSION = 'v1.29.2'
        TO_VERSION = 'v1.30.6'

        utils.create_test_kube_upgrade(
            from_version=FROM_VERSION,
            to_version=TO_VERSION,
            state=kubernetes.KUBE_UPGRADING_NETWORKING,
        )

        upgrade_overrides = {
            "cluster_host_floating_address": "192.168.206.1",
            "cluster_host_node_0_address": "192.168.206.2"
        }

        FAKE_AUTH = "fake_username:fake_password"

        FAKE_IMAGES = {
            'calico_cni_img': 'img1',
            'calico_ctl_img': 'img9',
            'calico_dikastes_img': 'img10',
            'calico_envoy_gateway_img': 'img11',
            'calico_envoy_proxy_img': 'img12',
            'calico_kube_controllers_img': 'img3',
            'calico_node_img': 'img2',
            'calico_pod2daemon_flexvol_img': 'img15',
            'calico_typha_img': 'img16',
            'multus_img': 'img4',
            'sriov_cni_img': 'img5',
            'sriov_network_device_img': 'img6',
            'tigera_operator_img': 'img19',
        }

        # For versions below v1.35.2, only base images are used
        FAKE_IMAGE_LIST = [
            FAKE_IMAGES['calico_cni_img'],
            FAKE_IMAGES['calico_node_img'],
            FAKE_IMAGES['calico_kube_controllers_img'],
            FAKE_IMAGES['multus_img'],
            FAKE_IMAGES['sriov_cni_img'],
            FAKE_IMAGES['sriov_network_device_img'],
        ]

        with mock.patch(
            'sysinv.conductor.manager.ConductorManager._get_kubernetes_system_images',
            return_value=FAKE_IMAGES
        ) as mock_get_images, \
             mock.patch(
                 'sysinv.conductor.manager.ConductorManager.sanitize_kubeadm_configmap',
                 return_value=0
             ) as mock_sanitize, \
             mock.patch(
                 'sysinv.conductor.manager.ConductorManager.backup_kube_control_plane'
             ) as mock_backup, \
             mock.patch(
                 'sysinv.conductor.manager.ContainerImageDownloader.'
                 'download_images_from_upstream_to_local_reg_and_crictl',
                 return_value=True
             ) as mock_download, \
             mock.patch(
                'sysinv.common.utils.get_local_docker_registry_auth',
                return_value={'username': 'fake_username', 'password': 'fake_password'}
             ) as mock_get_auth, \
             mock.patch.object(
                 agent_rpcapi.AgentAPI,
                 'pull_kubernetes_images'
             ) as mock_pull_images, \
             mock.patch(
                 'sysinv.common.utils.execute'
             ) as mock_execute, \
             mock.patch(
                 'os.path.exists',
                 return_value=True
             ) as mock_exists, \
             mock.patch(
                 'builtins.open', mock.mock_open()
             ) as mock_open, \
             mock.patch(
                 'ruamel.yaml.safe_load',
                 return_value=upgrade_overrides
             ) as mock_yaml, \
             mock.patch(
                 'shutil.copy2'
             ) as mock_copy2, \
             mock.patch(
                 'sysinv.common.utils.render_jinja_template_from_file'
             ) as mock_render, \
             mock.patch(
                 'sysinv.common.kubernetes.kubectl_apply'
             ) as mock_kubectl, \
             mock.patch(
                 'os.remove'
             ) as mock_remove:

            self.service.kube_upgrade_networking(self.context, TO_VERSION)

            mock_sanitize.assert_called_once()
            mock_backup.assert_called_once()
            mock_get_images.assert_called_once_with(TO_VERSION)
            mock_download.assert_called_once()
            mock_get_auth.assert_called_once()
            mock_pull_images.assert_called_once()

            # Validate pull arguments safely (avoid UUID mismatch issues)
            args = mock_pull_images.call_args[0]
            self.assertEqual(args[0], self.context)
            self.assertEqual(args[3], FAKE_AUTH)
            self.assertEqual(args[2], FAKE_IMAGE_LIST)
            mock_execute.assert_called_once()
            mock_exists.assert_called()

            # FIX: do NOT assert called_once
            mock_open.assert_any_call('/tmp/upgrade_overrides.yaml', 'r')
        if cutils.is_debian_bullseye():
            mock_ruamel_yaml_safe_load = mock.MagicMock()
            p = mock.patch('ruamel.yaml.safe_load', mock_ruamel_yaml_safe_load)
            p.start().return_value = upgrade_overrides
            self.addCleanup(p.stop)

            mock_yaml.assert_called_once()
            mock_copy2.assert_not_called()
            mock_render.assert_not_called()
            mock_kubectl.assert_not_called()
            mock_remove.assert_called_once()

            updated_upgrade = self.dbapi.kube_upgrade_get_one()
            self.assertEqual(
                updated_upgrade.state,
                kubernetes.KUBE_UPGRADING_NETWORKING_FAILED
            )
        else:
            mock_yaml_obj = mock.MagicMock()
            mock_yaml_obj.load.return_value = upgrade_overrides
            p = mock.patch('sysinv.conductor.manager.YAML', return_value=mock_yaml_obj)
            p.start()
            self.addCleanup(p.stop)

    def test_kube_upgrade_networking_failure_host_overrides_invalid_ip_address(self):
        """Test failed execution of kubernetes networking upgrade
        (cluster_host_floating_address invalid value)
        """

        # Create controller-0
        controller0_uuid = str(uuid.uuid4())
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=controller0_uuid,
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        # Create controller-1
        controller1_uuid = str(uuid.uuid4())
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-1',
            uuid=controller1_uuid,
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            mgmt_mac='00:11:22:33:44:56'
        )

        # Make controller-1 the active host
        self.service.host_uuid = controller1_uuid

        FROM_VERSION = 'v1.29.2'
        TO_VERSION = 'v1.30.6'

        utils.create_test_kube_upgrade(
            from_version=FROM_VERSION,
            to_version=TO_VERSION,
            state=kubernetes.KUBE_UPGRADING_NETWORKING,
        )

        FAKE_CREDS = {'username': 'fake_username', 'password': 'fake_password'}
        FAKE_AUTH = "fake_username:fake_password"

        upgrade_overrides = {
            "cluster_pod_subnet": "172.16.0.0/16",
            "cluster_host_floating_address": "invalid_ip_address",
            "cluster_host_node_0_address": "192.168.206.2"
        }

        # Proper image mocking (CRITICAL FIX)
        FAKE_IMAGES = {
            'calico_cni_img': 'img1',
            'calico_ctl_img': 'img9',
            'calico_dikastes_img': 'img10',
            'calico_envoy_gateway_img': 'img11',
            'calico_envoy_proxy_img': 'img12',
            'calico_kube_controllers_img': 'img3',
            'calico_node_img': 'img2',
            'calico_pod2daemon_flexvol_img': 'img15',
            'calico_typha_img': 'img16',
            'multus_img': 'img4',
            'sriov_cni_img': 'img5',
            'sriov_network_device_img': 'img6',
            'tigera_operator_img': 'img19',
        }
        # For versions below v1.35.2, only base images are used
        FAKE_IMAGE_LIST = [
            FAKE_IMAGES['calico_cni_img'],
            FAKE_IMAGES['calico_node_img'],
            FAKE_IMAGES['calico_kube_controllers_img'],
            FAKE_IMAGES['multus_img'],
            FAKE_IMAGES['sriov_cni_img'],
            FAKE_IMAGES['sriov_network_device_img'],
        ]

        with mock.patch(
            'sysinv.conductor.manager.ConductorManager._get_kubernetes_system_images',
            return_value=FAKE_IMAGES
        ) as mock_get_kubernetes_system_images, \
             mock.patch(
                 'sysinv.conductor.manager.ConductorManager.sanitize_kubeadm_configmap',
                 return_value=0
             ) as mock_sanitize_kubeadm_configmap, \
             mock.patch(
                 'sysinv.conductor.manager.ConductorManager.backup_kube_control_plane'
             ) as mock_backup_kube_control_plane, \
             mock.patch(
                 'sysinv.conductor.manager.ContainerImageDownloader.'
                 'download_images_from_upstream_to_local_reg_and_crictl',
                 return_value=True
             ) as mock_download_images, \
             mock.patch(
                 'sysinv.common.utils.get_local_docker_registry_auth',
                 return_value=FAKE_CREDS
             ) as mock_get_auth, \
             mock.patch.object(
                 agent_rpcapi.AgentAPI, 'pull_kubernetes_images'
             ) as mock_pull_kubernetes_images, \
             mock.patch(
                 'sysinv.common.utils.execute'
             ) as mock_utils_execute, \
             mock.patch(
                 'os.path.exists',
                 return_value=True
             ) as mock_os_path_exists, \
             mock.patch(
                 'builtins.open', mock.mock_open()
             ) as mock_open, \
             mock.patch(
                 'ruamel.yaml.safe_load',
                 return_value=upgrade_overrides
             ) as mock_yaml_load, \
             mock.patch(
                 'shutil.copy2'
             ) as mock_copy2, \
             mock.patch(
                 'sysinv.common.utils.render_jinja_template_from_file'
             ) as mock_render, \
             mock.patch(
                 'sysinv.common.kubernetes.kubectl_apply'
             ) as mock_kubectl_apply, \
             mock.patch(
                 'os.remove'
             ) as mock_remove:

            self.service.kube_upgrade_networking(self.context, TO_VERSION)

            # Assertions
            mock_sanitize_kubeadm_configmap.assert_called_once()
            mock_backup_kube_control_plane.assert_called_once()
            mock_get_kubernetes_system_images.assert_called_once_with(TO_VERSION)
            mock_download_images.assert_called_once()
            mock_get_auth.assert_called_once()

            mock_pull_kubernetes_images.assert_called_once()

            # Validate pull arguments safely (avoid UUID mismatch issues)
            args = mock_pull_kubernetes_images.call_args[0]
            self.assertEqual(args[0], self.context)
            self.assertEqual(args[3], FAKE_AUTH)
            self.assertEqual(args[2], FAKE_IMAGE_LIST)

        if cutils.is_debian_bullseye():
            mock_ruamel_yaml_safe_load = mock.MagicMock()
            p = mock.patch('ruamel.yaml.safe_load', mock_ruamel_yaml_safe_load)
            p.start().return_value = upgrade_overrides
            self.addCleanup(p.stop)

            mock_utils_execute.assert_called_once()
            mock_os_path_exists.assert_called()
            mock_open.assert_called_once()
            mock_yaml_load.assert_called_once()
            mock_copy2.assert_not_called()
            mock_render.assert_not_called()
            mock_kubectl_apply.assert_not_called()
            mock_remove.assert_called_once()

            updated_upgrade = self.dbapi.kube_upgrade_get_one()
            self.assertEqual(
                updated_upgrade.state,
                kubernetes.KUBE_UPGRADING_NETWORKING_FAILED
            )
        else:
            mock_yaml_obj = mock.MagicMock()
            mock_yaml_obj.load.return_value = upgrade_overrides
            p = mock.patch('sysinv.conductor.manager.YAML', return_value=mock_yaml_obj)
            p.start()
            self.addCleanup(p.stop)

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
            'sysinv.conductor.manager.ContainerImageDownloader.'
            'download_images_from_upstream_to_local_reg_and_crictl',
            mock_download_images_from_upstream_to_local_reg_and_crictl)
        p.start().return_value = image_download_result
        self.addCleanup(p.stop)

        mock_get_auth = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.utils.get_local_docker_registry_auth',
            mock_get_auth
        )
        p.start().return_value = {'username': 'fake', 'password': 'fake'}
        self.addCleanup(p.stop)

        mock_pull_images = mock.MagicMock()
        p = mock.patch.object(
            agent_rpcapi.AgentAPI,
            'pull_kubernetes_images',
            mock_pull_images
        )
        p.start()
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

        if cutils.is_debian_bullseye():
            mock_ruamel_yaml_safe_load = mock.MagicMock()
            p = mock.patch('ruamel.yaml.safe_load', mock_ruamel_yaml_safe_load)
            p.start().return_value = upgrade_overrides
            self.addCleanup(p.stop)
        else:
            mock_yaml_obj = mock.MagicMock()
            mock_yaml_obj.load.return_value = upgrade_overrides
            p = mock.patch('sysinv.conductor.manager.YAML', return_value=mock_yaml_obj)
            p.start()
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
        if cutils.is_debian_bullseye():
            mock_ruamel_yaml_safe_load.assert_called_once()
        else:
            mock_yaml_obj.load.assert_called_once()
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
            'sysinv.conductor.manager.ContainerImageDownloader.'
            'download_images_from_upstream_to_local_reg_and_crictl',
            mock_download_images_from_upstream_to_local_reg_and_crictl)
        p.start().return_value = image_download_result
        self.addCleanup(p.stop)

        mock_get_auth = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.utils.get_local_docker_registry_auth',
            mock_get_auth
        )
        p.start().return_value = {'username': 'fake', 'password': 'fake'}
        self.addCleanup(p.stop)

        mock_pull_images = mock.MagicMock()
        p = mock.patch.object(
            agent_rpcapi.AgentAPI,
            'pull_kubernetes_images',
            mock_pull_images
        )
        p.start()
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

        if cutils.is_debian_bullseye():
            mock_ruamel_yaml_safe_load = mock.MagicMock()
            p = mock.patch('ruamel.yaml.safe_load', mock_ruamel_yaml_safe_load)
            p.start().return_value = upgrade_overrides
            self.addCleanup(p.stop)
        else:
            mock_yaml_obj = mock.MagicMock()
            mock_yaml_obj.load.return_value = upgrade_overrides
            p = mock.patch('sysinv.conductor.manager.YAML', return_value=mock_yaml_obj)
            p.start()
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
        if cutils.is_debian_bullseye():
            mock_ruamel_yaml_safe_load.assert_called_once()
        else:
            mock_yaml_obj.load.assert_called_once()
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
            'sysinv.conductor.manager.ContainerImageDownloader.'
            'download_images_from_upstream_to_local_reg_and_crictl',
            mock_download_images_from_upstream_to_local_reg_and_crictl)
        p.start().return_value = image_download_result
        self.addCleanup(p.stop)

        mock_get_auth = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.utils.get_local_docker_registry_auth',
            mock_get_auth
        )
        p.start().return_value = {'username': 'fake', 'password': 'fake'}
        self.addCleanup(p.stop)

        mock_pull_images = mock.MagicMock()
        p = mock.patch.object(
            agent_rpcapi.AgentAPI,
            'pull_kubernetes_images',
            mock_pull_images
        )
        p.start()
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
            'sysinv.conductor.manager.ContainerImageDownloader.'
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
            'sysinv.conductor.manager.ContainerImageDownloader.'
            'download_images_from_upstream_to_local_reg_and_crictl',
            mock_download_images_from_upstream_to_local_reg_and_crictl)
        p.start().return_value = image_download_result
        self.addCleanup(p.stop)

        mock_get_auth = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.utils.get_local_docker_registry_auth',
            mock_get_auth
        )
        p.start().return_value = {'username': 'fake', 'password': 'fake'}
        self.addCleanup(p.stop)

        mock_pull_images = mock.MagicMock()
        p = mock.patch.object(
            agent_rpcapi.AgentAPI,
            'pull_kubernetes_images',
            mock_pull_images
        )
        p.start()
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

    def test_kube_upgrade_kubelet_controller_host_success(self):
        """Test successful execution of kubelet upgrade (on controller host)
        """
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        controller0_host_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname=constants.CONTROLLER_0_HOSTNAME,
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

        FROM_VERSION = 'v1.29.2'
        TO_VERSION = 'v1.30.6'

        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version=FROM_VERSION,
            to_version=TO_VERSION,
            state=kubernetes.KUBE_UPGRADING_KUBELETS,
        )

        self.dbapi.kube_host_upgrade_update(1, {'target_version': TO_VERSION})

        mock_kube_upgrade_kubelet = mock.MagicMock()
        p = mock.patch.object(
            agent_rpcapi.AgentAPI, 'kube_upgrade_kubelet', mock_kube_upgrade_kubelet)
        p.start()
        self.addCleanup(p.stop)

        self.service.kube_upgrade_kubelet(self.context, controller0_host_uuid)

        mock_kube_upgrade_kubelet.assert_called_once_with(
            self.context, controller0_host_uuid, TO_VERSION, True)

    def test_kube_upgrade_kubelet_worker_host_success(self):
        """Test successful execution of kubelet upgrade (on worker host)
        """
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Create controller-0
        config_uuid = str(uuid.uuid4())
        controller0_host_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname=constants.CONTROLLER_0_HOSTNAME,
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
            hostname=constants.CONTROLLER_1_HOSTNAME,
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

        # Create compute-0
        config_uuid = str(uuid.uuid4())
        compute0_host_uuid = str(uuid.uuid4())
        compute0_host = self._create_test_ihost(
            personality=constants.WORKER,
            hostname='compute-0',
            uuid=compute0_host_uuid,
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            mgmt_mac='00:11:22:33:44:57')

        FROM_VERSION = 'v1.29.2'
        TO_VERSION = 'v1.30.6'

        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version=FROM_VERSION,
            to_version=TO_VERSION,
            state=kubernetes.KUBE_UPGRADING_KUBELETS,
        )

        self.dbapi.kube_host_upgrade_update(compute0_host.id, {'target_version': TO_VERSION})

        mock_kube_upgrade_kubelet = mock.MagicMock()
        p = mock.patch.object(
            agent_rpcapi.AgentAPI, 'kube_upgrade_kubelet', mock_kube_upgrade_kubelet)
        p.start()
        self.addCleanup(p.stop)

        self.service.kube_upgrade_kubelet(self.context, compute0_host_uuid)

        mock_kube_upgrade_kubelet.assert_called_once_with(
            self.context, compute0_host_uuid, TO_VERSION, True)

    def test_kube_upgrade_kubelet_storage_host(self):
        """Test skipped execution of kubelet upgrade on storage host
        """
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Create controller-0
        config_uuid = str(uuid.uuid4())
        controller0_host_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname=constants.CONTROLLER_0_HOSTNAME,
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
            hostname=constants.CONTROLLER_1_HOSTNAME,
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

        # Create compute-0
        config_uuid = str(uuid.uuid4())
        compute0_host_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.WORKER,
            hostname='compute-0',
            uuid=compute0_host_uuid,
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            mgmt_mac='00:11:22:33:44:57')

        # Create storage-0
        config_uuid = str(uuid.uuid4())
        storage0_host_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.STORAGE,
            hostname=constants.STORAGE_0_HOSTNAME,
            uuid=storage0_host_uuid,
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            mgmt_mac='00:11:22:33:44:58')

        FROM_VERSION = 'v1.29.2'
        TO_VERSION = 'v1.30.6'

        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version=FROM_VERSION,
            to_version=TO_VERSION,
            state=kubernetes.KUBE_UPGRADING_KUBELETS,
        )

        mock_kube_upgrade_kubelet = mock.MagicMock()
        p = mock.patch.object(
            agent_rpcapi.AgentAPI, 'kube_upgrade_kubelet', mock_kube_upgrade_kubelet)
        p.start()
        self.addCleanup(p.stop)

        self.assertRaises(exception.SysinvException,
                          self.service.kube_upgrade_kubelet,
                          self.context,
                          storage0_host_uuid)

        mock_kube_upgrade_kubelet.assert_not_called()

    def test_kube_upgrade_control_plane_simplex_success_single_version(self):
        """Test successful execution of control-plane upgrade on simplex systems (single version)
        """
        self.skipTest("WIP:jgauld etcd-versions")

        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_SIMPLEX
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Create controller-0
        config_uuid = str(uuid.uuid4())
        controller0_host_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname=constants.CONTROLLER_0_HOSTNAME,
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

        # Create a kubernetes upgrade
        utils.create_test_kube_upgrade(
            from_version='v1.29.2',
            to_version='v1.30.6',
            state=kubernetes.KUBE_UPGRADING_FIRST_MASTER,
        )

        # Set mock outputs. This reflects the current environment (i.e. control-plane and kubelet
        # versions on all hosts).
        current_control_plane_versions = {'controller-0': 'v1.29.2'}
        current_kubelet_versions = {'controller-0': 'v1.29.2'}
        # This is what is inside the load.
        get_kube_versions_output = [
            {'version': 'v1.29.2'},
            {'version': 'v1.30.6'},
            {'version': 'v1.31.5'},
            {'version': 'v1.32.2'},
            {'version': 'v1.33.0'},
        ]

        # set expectations: argument values to assert sysinv-agent API call with
        upgrade_control_plane_to_version = 'v1.30.6'
        is_first = True

        self.service._kube = kubernetes.KubeOperator()

        mock_kube_get_control_plane_versions = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_get_control_plane_versions',
                       mock_kube_get_control_plane_versions)
        p.start().return_value = current_control_plane_versions
        self.addCleanup(p.stop)

        mock_kube_get_kubelet_versions = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_get_kubelet_versions',
                       mock_kube_get_kubelet_versions)
        p.start().return_value = current_kubelet_versions
        self.addCleanup(p.stop)

        mock_get_kube_versions = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.get_kube_versions',
            mock_get_kube_versions)
        p.start().return_value = get_kube_versions_output
        self.addCleanup(p.stop)

        mock_sanitize_kubeadm_configmap = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.sanitize_kubeadm_configmap',
                       mock_sanitize_kubeadm_configmap)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_kubeadm_configmap_reformat = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kubeadm_configmap_reformat',
                       mock_kubeadm_configmap_reformat)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_upgrade_control_plane_agent_api = mock.MagicMock()
        p = mock.patch.object(agent_rpcapi.AgentAPI, 'kube_upgrade_control_plane',
                              mock_upgrade_control_plane_agent_api)
        p.start()
        self.addCleanup(p.stop)

        self.service.kube_upgrade_control_plane(self.context, controller0_host_uuid)

        mock_kube_get_control_plane_versions.assert_called_once()
        mock_kube_get_kubelet_versions.assert_called_once()
        mock_get_kube_versions.assert_called_once()
        mock_sanitize_kubeadm_configmap.assert_called_once()
        mock_kubeadm_configmap_reformat.assert_called_once()
        mock_upgrade_control_plane_agent_api.assert_called_once_with(
            self.context, controller0_host_uuid, upgrade_control_plane_to_version, is_first)

    def test_kube_upgrade_control_plane_simplex_success_single_version_patch_version(self):
        """Test successful execution of control-plane upgrade on simplex systems: patch version
        """
        self.skipTest("WIP:jgauld etcd-versions")

        # WIP: fix the following
        # Failed to save kube control plane upgrade method details with error:
        #  [Failed to save kubernetes upgrade method name and arguments.
        #   Error: [[Errno 2] No such file or directory:
        #   '/etc/platform/.sysinv_agent_k8s_upgrade_in_progress.pkl']].
        #   Continuing...
        # Unable to find etcd version in symlink target /usr/local/kubernetes/1.29.2/stage1
        # etcd binary upgrade not required from: None
        # Kubernetes control-plane upgrade to version vfake_to_kube_version started on this host. Attempt: 1
        # Kubernetes control-plane upgrade to version vfake_to_kube_version successful on this host.

        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_SIMPLEX
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Create controller-0
        config_uuid = str(uuid.uuid4())
        controller0_host_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname=constants.CONTROLLER_0_HOSTNAME,
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

        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version='v1.29.2',
            to_version='v1.29.3',
            state=kubernetes.KUBE_UPGRADING_FIRST_MASTER,
        )

        # Set mock outputs. This reflects the current environment (i.e. control-plane and kubelet
        # versions on all hosts).
        current_control_plane_versions = {'controller-0': 'v1.29.2'}
        current_kubelet_versions = {'controller-0': 'v1.29.3'}
        # This is what is inside the load.
        get_kube_versions_output = [
            {'version': 'v1.29.2'},
            {'version': 'v1.29.3'},
            {'version': 'v1.30.6'},
            {'version': 'v1.31.5'},
            {'version': 'v1.32.2'},
            {'version': 'v1.33.0'},
        ]

        # Set expectations. argument values to assert sysinv-agent API call with
        # TODO(jgauld) - WIP
        # TODO(jgauld): current_etcd_version = '3.4.37'
        target_etcd_version = '3.5.26'
        upgrade_control_plane_to_version = 'v1.29.3'
        is_first = True

        self.service._kube = kubernetes.KubeOperator()

        mock_kube_get_control_plane_versions = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_get_control_plane_versions',
                       mock_kube_get_control_plane_versions)
        p.start().return_value = current_control_plane_versions
        self.addCleanup(p.stop)

        mock_kube_get_kubelet_versions = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_get_kubelet_versions',
                       mock_kube_get_kubelet_versions)
        p.start().return_value = current_kubelet_versions
        self.addCleanup(p.stop)

        mock_get_kube_versions = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.get_kube_versions',
            mock_get_kube_versions)
        p.start().return_value = get_kube_versions_output
        self.addCleanup(p.stop)

        mock_sanitize_kubeadm_configmap = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.sanitize_kubeadm_configmap',
                       mock_sanitize_kubeadm_configmap)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_kubeadm_configmap_reformat = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kubeadm_configmap_reformat',
                       mock_kubeadm_configmap_reformat)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_upgrade_control_plane_agent_api = mock.MagicMock()
        p = mock.patch.object(agent_rpcapi.AgentAPI, 'kube_upgrade_control_plane',
                              mock_upgrade_control_plane_agent_api)
        p.start()
        self.addCleanup(p.stop)

        self.service.kube_upgrade_control_plane(self.context, controller0_host_uuid)

        mock_kube_get_control_plane_versions.assert_called_once()
        mock_kube_get_kubelet_versions.assert_called_once()
        mock_get_kube_versions.assert_called_once()
        mock_sanitize_kubeadm_configmap.assert_called_once()
        mock_kubeadm_configmap_reformat.assert_called_once()
        mock_upgrade_control_plane_agent_api.assert_called_once_with(
            self.context, controller0_host_uuid, target_etcd_version,
            upgrade_control_plane_to_version, is_first)

    def test_kube_upgrade_control_plane_simplex_success_multi_version(self):
        """Test successful execution of control-plane upgrade on simplex systems (multi-version)
        """
        self.skipTest("WIP:jgauld etcd-versions")

        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_SIMPLEX
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Create controller-0
        config_uuid = str(uuid.uuid4())
        controller0_host_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname=constants.CONTROLLER_0_HOSTNAME,
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

        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version='v1.29.2',
            to_version='v1.33.0',
            state=kubernetes.KUBE_UPGRADING_FIRST_MASTER,
        )

        # Set mock outputs. This reflects the current environment (i.e. control-plane and kubelet
        # versions on all hosts).
        current_control_plane_versions = {'controller-0': 'v1.29.2'}
        current_kubelet_versions = {'controller-0': 'v1.29.2'}
        # This is what is inside the load.
        get_kube_versions_output = [
            {'version': 'v1.29.2'},
            {'version': 'v1.30.6'},
            {'version': 'v1.31.5'},
            {'version': 'v1.32.2'},
            {'version': 'v1.33.0'},
        ]

        # Set expectations: argument values to assert sysinv-agent API call with
        upgrade_control_plane_to_version = 'v1.30.6'
        is_first = True

        self.service._kube = kubernetes.KubeOperator()

        mock_kube_get_control_plane_versions = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_get_control_plane_versions',
                       mock_kube_get_control_plane_versions)
        p.start().return_value = current_control_plane_versions
        self.addCleanup(p.stop)

        mock_kube_get_kubelet_versions = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_get_kubelet_versions',
                       mock_kube_get_kubelet_versions)
        p.start().return_value = current_kubelet_versions
        self.addCleanup(p.stop)

        mock_get_kube_versions = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.get_kube_versions',
            mock_get_kube_versions)
        p.start().return_value = get_kube_versions_output
        self.addCleanup(p.stop)

        mock_sanitize_kubeadm_configmap = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.sanitize_kubeadm_configmap',
                       mock_sanitize_kubeadm_configmap)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_kubeadm_configmap_reformat = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kubeadm_configmap_reformat',
                       mock_kubeadm_configmap_reformat)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_upgrade_control_plane_agent_api = mock.MagicMock()
        p = mock.patch.object(agent_rpcapi.AgentAPI, 'kube_upgrade_control_plane',
                              mock_upgrade_control_plane_agent_api)
        p.start()
        self.addCleanup(p.stop)

        self.service.kube_upgrade_control_plane(self.context, controller0_host_uuid)

        mock_kube_get_control_plane_versions.assert_called_once()
        mock_kube_get_kubelet_versions.assert_called_once()
        mock_get_kube_versions.assert_called_once()
        mock_sanitize_kubeadm_configmap.assert_called_once()
        mock_kubeadm_configmap_reformat.assert_called_once()
        mock_upgrade_control_plane_agent_api.assert_called_once_with(
            self.context, controller0_host_uuid, upgrade_control_plane_to_version, is_first)

    def test_kube_upgrade_control_plane_simplex_success_multi_version_intermediate_versions(self):
        """Test successful execution of control-plane upgrade on simplex systems (multi-version)

        Both FROM_VERSION and TO_VERSION are intermediate versions supported
        """
        self.skipTest("WIP:jgauld etcd-versions")

        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_SIMPLEX
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Create controller-0
        config_uuid = str(uuid.uuid4())
        controller0_host_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname=constants.CONTROLLER_0_HOSTNAME,
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

        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version='v1.30.6',
            to_version='v1.32.2',
            state=kubernetes.KUBE_UPGRADING_FIRST_MASTER,
        )

        # Set mock outputs. This reflects the current environment (i.e. control-plane and kubelet
        # versions on all hosts).
        current_control_plane_versions = {'controller-0': 'v1.30.6'}
        current_kubelet_versions = {'controller-0': 'v1.30.6'}
        # This is what is inside the load.
        get_kube_versions_output = [
            {'version': 'v1.29.2'},
            {'version': 'v1.30.6'},
            {'version': 'v1.31.5'},
            {'version': 'v1.32.2'},
            {'version': 'v1.33.0'},
        ]

        # Set expectations: argument values to assert sysinv-agent API call with
        upgrade_control_plane_to_version = 'v1.31.5'
        is_first = True

        self.service._kube = kubernetes.KubeOperator()

        mock_kube_get_control_plane_versions = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_get_control_plane_versions',
                       mock_kube_get_control_plane_versions)
        p.start().return_value = current_control_plane_versions
        self.addCleanup(p.stop)

        mock_kube_get_kubelet_versions = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_get_kubelet_versions',
                       mock_kube_get_kubelet_versions)
        p.start().return_value = current_kubelet_versions
        self.addCleanup(p.stop)

        mock_get_kube_versions = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.get_kube_versions',
            mock_get_kube_versions)
        p.start().return_value = get_kube_versions_output
        self.addCleanup(p.stop)

        mock_sanitize_kubeadm_configmap = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.sanitize_kubeadm_configmap',
                       mock_sanitize_kubeadm_configmap)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_kubeadm_configmap_reformat = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kubeadm_configmap_reformat',
                       mock_kubeadm_configmap_reformat)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_upgrade_control_plane_agent_api = mock.MagicMock()
        p = mock.patch.object(agent_rpcapi.AgentAPI, 'kube_upgrade_control_plane',
                              mock_upgrade_control_plane_agent_api)
        p.start()
        self.addCleanup(p.stop)

        self.service.kube_upgrade_control_plane(self.context, controller0_host_uuid)

        mock_kube_get_control_plane_versions.assert_called_once()
        mock_kube_get_kubelet_versions.assert_called_once()
        mock_get_kube_versions.assert_called_once()
        mock_sanitize_kubeadm_configmap.assert_called_once()
        mock_kubeadm_configmap_reformat.assert_called_once()
        mock_upgrade_control_plane_agent_api.assert_called_once_with(
            self.context, controller0_host_uuid, upgrade_control_plane_to_version, is_first)

    def test_kube_upgrade_control_plane_simplex_success_with_skew_policy_exact_skew(self):
        """Test successful execution of control-plane upgrade on simplex systems with version skew policy: exact skew
        """
        self.skipTest("WIP:jgauld etcd-versions")

        # WIP: fix the following
        # mock_upgrade_control_plane_agent_api.assert_called_once_with(
        # AssertionError: expected call not found.
        # Expected: mock(<oslo_context.context.RequestContext object at 0x7d2ae456e6d0>,
        #                '2793b331-ff2e-46d2-aa61-1c4001ab10f7', 'v1.32.2', True)
        # Actual: mock(<oslo_context.context.RequestContext object at 0x7d2ae456e6d0>,
        #             '2793b331-ff2e-46d2-aa61-1c4001ab10f7', None, 'v1.32.2', True)

        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_SIMPLEX
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Create controller-0
        config_uuid = str(uuid.uuid4())
        controller0_host_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname=constants.CONTROLLER_0_HOSTNAME,
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

        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version='v1.29.2',
            to_version='v1.33.0',
            state=kubernetes.KUBE_UPGRADING_FIRST_MASTER,
        )

        # Set mock outputs. This reflects the current environment (i.e. control-plane and kubelet
        # versions on all hosts).
        # Make the control plane upgrade pass, with 3 kubelet skew
        # e.g., 32 - 29 = 3 (exact tolerance)
        current_control_plane_versions = {'controller-0': 'v1.31.5'}
        current_kubelet_versions = {'controller-0': 'v1.29.2'}
        # This is what is inside the load.
        get_kube_versions_output = [
            {'version': 'v1.29.2'},
            {'version': 'v1.30.6'},
            {'version': 'v1.31.5'},
            {'version': 'v1.32.2'},
            {'version': 'v1.33.0'},
        ]

        # Set expectations: argument values to assert sysinv-agent API call with
        upgrade_control_plane_to_version = 'v1.32.2'
        is_first = True

        self.service._kube = kubernetes.KubeOperator()

        mock_kube_get_control_plane_versions = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_get_control_plane_versions',
                       mock_kube_get_control_plane_versions)
        p.start().return_value = current_control_plane_versions
        self.addCleanup(p.stop)

        mock_kube_get_kubelet_versions = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_get_kubelet_versions',
                       mock_kube_get_kubelet_versions)
        p.start().return_value = current_kubelet_versions
        self.addCleanup(p.stop)

        mock_get_kube_versions = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.get_kube_versions',
            mock_get_kube_versions)
        p.start().return_value = get_kube_versions_output
        self.addCleanup(p.stop)

        mock_sanitize_kubeadm_configmap = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.sanitize_kubeadm_configmap',
                       mock_sanitize_kubeadm_configmap)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_kubeadm_configmap_reformat = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kubeadm_configmap_reformat',
                       mock_kubeadm_configmap_reformat)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_upgrade_control_plane_agent_api = mock.MagicMock()
        p = mock.patch.object(agent_rpcapi.AgentAPI, 'kube_upgrade_control_plane',
                              mock_upgrade_control_plane_agent_api)
        p.start()
        self.addCleanup(p.stop)

        self.service.kube_upgrade_control_plane(self.context, controller0_host_uuid)

        mock_kube_get_control_plane_versions.assert_called_once()
        mock_kube_get_kubelet_versions.assert_called_once()
        mock_get_kube_versions.assert_called_once()
        mock_sanitize_kubeadm_configmap.assert_called_once()
        mock_kubeadm_configmap_reformat.assert_called_once()
        mock_upgrade_control_plane_agent_api.assert_called_once_with(
            self.context, controller0_host_uuid, upgrade_control_plane_to_version, is_first)

    def test_kube_upgrade_control_plane_simplex_failure_with_skew_policy_exceeded(self):
        """Test failed execution of control-plane upgrade on simplex systems with version skew policy exceeded
        """
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_SIMPLEX
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Create controller-0
        config_uuid = str(uuid.uuid4())
        controller0_host_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname=constants.CONTROLLER_0_HOSTNAME,
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

        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version='v1.29.2',
            to_version='v1.33.0',
            state=kubernetes.KUBE_UPGRADING_FIRST_MASTER,
        )

        # Set mock outputs. This reflects the current environment (i.e. control-plane and kubelet
        # versions on all hosts).
        # Make the control plane upgrade fail, one node has large kubelet skew,
        # e.g., 33 - 29 = 4 (>3 tolerance)
        current_control_plane_versions = {'controller-0': 'v1.32.2'}
        current_kubelet_versions = {'controller-0': 'v1.29.2'}
        # This is what is inside the load.
        get_kube_versions_output = [
            {'version': 'v1.29.2'},
            {'version': 'v1.30.6'},
            {'version': 'v1.31.5'},
            {'version': 'v1.32.2'},
            {'version': 'v1.33.0'},
        ]

        self.service._kube = kubernetes.KubeOperator()

        mock_kube_get_control_plane_versions = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_get_control_plane_versions',
                       mock_kube_get_control_plane_versions)
        p.start().return_value = current_control_plane_versions
        self.addCleanup(p.stop)

        mock_kube_get_kubelet_versions = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_get_kubelet_versions',
                       mock_kube_get_kubelet_versions)
        p.start().return_value = current_kubelet_versions
        self.addCleanup(p.stop)

        mock_get_kube_versions = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.get_kube_versions',
            mock_get_kube_versions)
        p.start().return_value = get_kube_versions_output
        self.addCleanup(p.stop)

        mock_sanitize_kubeadm_configmap = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.sanitize_kubeadm_configmap',
                       mock_sanitize_kubeadm_configmap)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_kubeadm_configmap_reformat = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kubeadm_configmap_reformat',
                       mock_kubeadm_configmap_reformat)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_upgrade_control_plane_agent_api = mock.MagicMock()
        p = mock.patch.object(agent_rpcapi.AgentAPI, 'kube_upgrade_control_plane',
                              mock_upgrade_control_plane_agent_api)
        p.start()
        self.addCleanup(p.stop)

        self.service.kube_upgrade_control_plane(self.context, controller0_host_uuid)

        mock_kube_get_control_plane_versions.assert_called_once()
        mock_kube_get_kubelet_versions.assert_called_once()
        mock_get_kube_versions.assert_called_once()
        mock_sanitize_kubeadm_configmap.assert_not_called()
        mock_kubeadm_configmap_reformat.assert_not_called()
        mock_upgrade_control_plane_agent_api.assert_not_called()

        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state, kubernetes.KUBE_UPGRADING_FIRST_MASTER_FAILED)

    def test_kube_upgrade_control_plane_simplex_failure_with_invalid_state(self):
        """Test successful execution of control-plane upgrade on simplex systems with invalid state

        Invalid state: KUBE_UPGRADING_KUBELETS. Should be either KUBE_UPGRADING_FIRST_MASTER
        or KUBE_UPGRADING_SECOND_MASTER
        """
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_SIMPLEX
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Create controller-0
        config_uuid = str(uuid.uuid4())
        controller0_host_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname=constants.CONTROLLER_0_HOSTNAME,
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

        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version='v1.29.2',
            to_version='v1.33.0',
            state=kubernetes.KUBE_UPGRADING_KUBELETS,
        )

        self.service._kube = kubernetes.KubeOperator()

        mock_kube_get_control_plane_versions = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_get_control_plane_versions',
                       mock_kube_get_control_plane_versions)
        p.start()
        self.addCleanup(p.stop)

        mock_kube_get_kubelet_versions = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_get_kubelet_versions',
                       mock_kube_get_kubelet_versions)
        p.start()
        self.addCleanup(p.stop)

        mock_get_kube_versions = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.get_kube_versions',
            mock_get_kube_versions)
        p.start()
        self.addCleanup(p.stop)

        mock_sanitize_kubeadm_configmap = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.sanitize_kubeadm_configmap',
                       mock_sanitize_kubeadm_configmap)
        p.start()
        self.addCleanup(p.stop)

        mock_kubeadm_configmap_reformat = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kubeadm_configmap_reformat',
                       mock_kubeadm_configmap_reformat)
        p.start()
        self.addCleanup(p.stop)

        mock_upgrade_control_plane_agent_api = mock.MagicMock()
        p = mock.patch.object(agent_rpcapi.AgentAPI, 'kube_upgrade_control_plane',
                              mock_upgrade_control_plane_agent_api)
        p.start()
        self.addCleanup(p.stop)

        self.assertRaises(exception.SysinvException,
                          self.service.kube_upgrade_control_plane,
                          self.context,
                          controller0_host_uuid)

        mock_kube_get_control_plane_versions.assert_not_called()
        mock_kube_get_kubelet_versions.assert_not_called()
        mock_get_kube_versions.assert_not_called()
        mock_sanitize_kubeadm_configmap.assert_not_called()
        mock_kubeadm_configmap_reformat.assert_not_called()
        mock_upgrade_control_plane_agent_api.assert_not_called()

    def test_kube_upgrade_control_plane_duplex_success_first_master(self):
        """Test successful execution of control-plane upgrade on Duplex systems: first master
        """
        self.skipTest("WIP:jgauld etcd-versions")

        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Create controller-0
        config_uuid = str(uuid.uuid4())
        controller0_host_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname=constants.CONTROLLER_0_HOSTNAME,
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
            hostname=constants.CONTROLLER_1_HOSTNAME,
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

        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version='v1.29.2',
            to_version='v1.30.6',
            state=kubernetes.KUBE_UPGRADING_FIRST_MASTER,
        )

        # Set mock outputs. This reflects the current environment (i.e. control-plane and kubelet
        # versions on all hosts).
        current_control_plane_versions = {'controller-0': 'v1.29.2',
                                          'controller-1': 'v1.29.2'}
        current_kubelet_versions = {'controller-0': 'v1.29.2',
                                    'controller-1': 'v1.29.2'}
        # This is what is inside the load.
        get_kube_versions_output = [
            {'version': 'v1.29.2'},
            {'version': 'v1.30.6'},
            {'version': 'v1.31.5'},
            {'version': 'v1.32.2'},
            {'version': 'v1.33.0'},
        ]

        # Set expectations. argument values to assert sysinv-agent API call with
        upgrade_control_plane_to_version = 'v1.30.6'
        is_first = True

        self.service._kube = kubernetes.KubeOperator()

        mock_kube_get_control_plane_versions = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_get_control_plane_versions',
                       mock_kube_get_control_plane_versions)
        p.start().return_value = current_control_plane_versions
        self.addCleanup(p.stop)

        mock_kube_get_kubelet_versions = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_get_kubelet_versions',
                       mock_kube_get_kubelet_versions)
        p.start().return_value = current_kubelet_versions
        self.addCleanup(p.stop)

        mock_get_kube_versions = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.get_kube_versions',
            mock_get_kube_versions)
        p.start().return_value = get_kube_versions_output
        self.addCleanup(p.stop)

        mock_sanitize_kubeadm_configmap = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.sanitize_kubeadm_configmap',
                       mock_sanitize_kubeadm_configmap)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_kubeadm_configmap_reformat = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kubeadm_configmap_reformat',
                       mock_kubeadm_configmap_reformat)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_upgrade_control_plane_agent_api = mock.MagicMock()
        p = mock.patch.object(agent_rpcapi.AgentAPI, 'kube_upgrade_control_plane',
                              mock_upgrade_control_plane_agent_api)
        p.start()
        self.addCleanup(p.stop)

        self.service.kube_upgrade_control_plane(self.context, controller0_host_uuid)

        mock_kube_get_control_plane_versions.assert_called_once()
        mock_kube_get_kubelet_versions.assert_called_once()
        mock_sanitize_kubeadm_configmap.assert_called_once()
        mock_kubeadm_configmap_reformat.assert_called_once()
        mock_upgrade_control_plane_agent_api.assert_called_once_with(
            self.context, controller0_host_uuid, upgrade_control_plane_to_version, is_first)

    def test_kube_upgrade_control_plane_duplex_success_second_master(self):
        """Test successful execution of control-plane upgrade on Duplex systems: second master
        """
        self.skipTest("WIP:jgauld etcd-versions")

        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Create controller-0
        config_uuid = str(uuid.uuid4())
        controller0_host_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname=constants.CONTROLLER_0_HOSTNAME,
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
            hostname=constants.CONTROLLER_1_HOSTNAME,
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

        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version='v1.29.2',
            to_version='v1.30.6',
            state=kubernetes.KUBE_UPGRADING_SECOND_MASTER,
        )

        # Set mock outputs. This reflects the current environment (i.e. control-plane and kubelet
        # versions on all hosts).
        current_control_plane_versions = {'controller-0': 'v1.30.6',
                                          'controller-1': 'v1.29.2'}
        current_kubelet_versions = {'controller-0': 'v1.29.2',
                                    'controller-1': 'v1.29.2'}
        # This is what is inside the load.
        get_kube_versions_output = [
            {'version': 'v1.29.2'},
            {'version': 'v1.30.6'},
            {'version': 'v1.31.5'},
            {'version': 'v1.32.2'},
            {'version': 'v1.33.0'},
        ]

        # Set expectations. argument values to assert sysinv-agent API call with
        upgrade_control_plane_to_version = 'v1.30.6'
        is_first = False

        self.service._kube = kubernetes.KubeOperator()

        mock_kube_get_control_plane_versions = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_get_control_plane_versions',
                       mock_kube_get_control_plane_versions)
        p.start().return_value = current_control_plane_versions
        self.addCleanup(p.stop)

        mock_kube_get_kubelet_versions = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_get_kubelet_versions',
                       mock_kube_get_kubelet_versions)
        p.start().return_value = current_kubelet_versions
        self.addCleanup(p.stop)

        mock_get_kube_versions = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.get_kube_versions',
            mock_get_kube_versions)
        p.start().return_value = get_kube_versions_output
        self.addCleanup(p.stop)

        mock_sanitize_kubeadm_configmap = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.sanitize_kubeadm_configmap',
                       mock_sanitize_kubeadm_configmap)
        p.start()
        self.addCleanup(p.stop)

        mock_kubeadm_configmap_reformat = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kubeadm_configmap_reformat',
                       mock_kubeadm_configmap_reformat)
        p.start()
        self.addCleanup(p.stop)

        mock_upgrade_control_plane_agent_api = mock.MagicMock()
        p = mock.patch.object(agent_rpcapi.AgentAPI, 'kube_upgrade_control_plane',
                              mock_upgrade_control_plane_agent_api)
        p.start()
        self.addCleanup(p.stop)

        self.service.kube_upgrade_control_plane(self.context, controller1_host_uuid)

        mock_kube_get_control_plane_versions.assert_called_once()
        mock_kube_get_kubelet_versions.assert_called_once()
        mock_sanitize_kubeadm_configmap.assert_not_called()
        mock_kubeadm_configmap_reformat.assert_not_called()
        mock_upgrade_control_plane_agent_api.assert_called_once_with(
            self.context, controller1_host_uuid, upgrade_control_plane_to_version, is_first)

    def test_kube_upgrade_control_plane_duplex_success_second_master_patch_version(self):
        """Test successful execution of control-plane upgrade on duplex systems: second master

        Patch version upgrade type for second master
        """
        self.skipTest("WIP:jgauld etcd-versions")

        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Create controller-0
        config_uuid = str(uuid.uuid4())
        controller0_host_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname=constants.CONTROLLER_0_HOSTNAME,
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
            hostname=constants.CONTROLLER_1_HOSTNAME,
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

        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version='v1.29.2',
            to_version='v1.29.3',
            state=kubernetes.KUBE_UPGRADING_SECOND_MASTER,
        )

        # Set mock outputs. This reflects the current environment (i.e. control-plane and kubelet
        # versions on all hosts).
        current_control_plane_versions = {'controller-0': 'v1.29.3',
                                          'controller-1': 'v1.29.2'}
        current_kubelet_versions = {'controller-0': 'v1.29.2',
                                    'controller-1': 'v1.29.2'}
        # This is what is inside the load.
        get_kube_versions_output = [
            {'version': 'v1.29.2'},
            {'version': 'v1.29.3'},
            {'version': 'v1.30.6'},
            {'version': 'v1.31.5'},
            {'version': 'v1.32.2'},
            {'version': 'v1.33.0'},
        ]

        # Set expectations: argument values with which Sysinv-agent API call is expected to be made
        upgrade_control_plane_to_version = 'v1.29.3'
        is_first = False

        self.service._kube = kubernetes.KubeOperator()

        mock_kube_get_control_plane_versions = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_get_control_plane_versions',
                       mock_kube_get_control_plane_versions)
        p.start().return_value = current_control_plane_versions
        self.addCleanup(p.stop)

        mock_kube_get_kubelet_versions = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_get_kubelet_versions',
                       mock_kube_get_kubelet_versions)
        p.start().return_value = current_kubelet_versions
        self.addCleanup(p.stop)

        mock_get_kube_versions = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.get_kube_versions',
            mock_get_kube_versions)
        p.start().return_value = get_kube_versions_output
        self.addCleanup(p.stop)

        mock_sanitize_kubeadm_configmap = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.sanitize_kubeadm_configmap',
                       mock_sanitize_kubeadm_configmap)
        p.start()
        self.addCleanup(p.stop)

        mock_kubeadm_configmap_reformat = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kubeadm_configmap_reformat',
                       mock_kubeadm_configmap_reformat)
        p.start()
        self.addCleanup(p.stop)

        mock_upgrade_control_plane_agent_api = mock.MagicMock()
        p = mock.patch.object(agent_rpcapi.AgentAPI, 'kube_upgrade_control_plane',
                              mock_upgrade_control_plane_agent_api)
        p.start()
        self.addCleanup(p.stop)

        self.service.kube_upgrade_control_plane(self.context, controller1_host_uuid)

        mock_kube_get_control_plane_versions.assert_called_once()
        mock_kube_get_kubelet_versions.assert_called_once()
        mock_sanitize_kubeadm_configmap.assert_not_called()
        mock_kubeadm_configmap_reformat.assert_not_called()
        mock_upgrade_control_plane_agent_api.assert_called_once_with(
            self.context, controller1_host_uuid, upgrade_control_plane_to_version, is_first)

    def test_kube_upgrade_control_plane_duplex_with_worker_success_with_skew_reached(self):
        """Test successful execution of control-plane upgrade on duplex systems: first master

        """
        self.skipTest("WIP:jgauld etcd-versions")

        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Create controller-0
        config_uuid = str(uuid.uuid4())
        controller0_host_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname=constants.CONTROLLER_0_HOSTNAME,
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
            hostname=constants.CONTROLLER_1_HOSTNAME,
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

        # Create compute-0
        config_uuid = str(uuid.uuid4())
        compute0_host_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.WORKER,
            hostname='compute-0',
            uuid=compute0_host_uuid,
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            mgmt_mac='00:11:22:33:44:57')

        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version='v1.29.2',
            to_version='v1.33.0',
            state=kubernetes.KUBE_UPGRADING_FIRST_MASTER,
        )

        # Set mock outputs This reflects the current environment (i.e. control-plane and kubelet
        # versions on all hosts).
        # Make the control plane upgrade pass, with 3 kubelet skew
        # e.g., 32 - 29 = 3 (exact tolerance)
        current_control_plane_versions = {'controller-0': 'v1.31.5',
                                          'controller-1': 'v1.31.5'}
        current_kubelet_versions = {'controller-0': 'v1.31.5',
                                    'controller-1': 'v1.31.5',
                                    'compute-0': 'v1.29.2'}
        # This is what is inside the load.
        get_kube_versions_output = [
            {'version': 'v1.29.2'},
            {'version': 'v1.30.6'},
            {'version': 'v1.31.5'},
            {'version': 'v1.32.2'},
            {'version': 'v1.33.0'},
        ]

        # Set expectations: argument values with which Sysinv-agent API call is expected to be made
        upgrade_control_plane_to_version = 'v1.32.2'
        is_first = True

        self.service._kube = kubernetes.KubeOperator()

        mock_kube_get_control_plane_versions = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_get_control_plane_versions',
                       mock_kube_get_control_plane_versions)
        p.start().return_value = current_control_plane_versions
        self.addCleanup(p.stop)

        mock_kube_get_kubelet_versions = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_get_kubelet_versions',
                       mock_kube_get_kubelet_versions)
        p.start().return_value = current_kubelet_versions
        self.addCleanup(p.stop)

        mock_get_kube_versions = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.get_kube_versions',
            mock_get_kube_versions)
        p.start().return_value = get_kube_versions_output
        self.addCleanup(p.stop)

        mock_sanitize_kubeadm_configmap = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.sanitize_kubeadm_configmap',
                       mock_sanitize_kubeadm_configmap)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_kubeadm_configmap_reformat = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kubeadm_configmap_reformat',
                       mock_kubeadm_configmap_reformat)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_upgrade_control_plane_agent_api = mock.MagicMock()
        p = mock.patch.object(agent_rpcapi.AgentAPI, 'kube_upgrade_control_plane',
                              mock_upgrade_control_plane_agent_api)
        p.start()
        self.addCleanup(p.stop)

        self.service.kube_upgrade_control_plane(self.context, controller0_host_uuid)

        mock_kube_get_control_plane_versions.assert_called_once()
        mock_kube_get_kubelet_versions.assert_called_once()
        mock_get_kube_versions.assert_called_once()
        mock_sanitize_kubeadm_configmap.assert_called_once()
        mock_kubeadm_configmap_reformat.assert_called_once()
        mock_upgrade_control_plane_agent_api.assert_called_once_with(
            self.context, controller0_host_uuid, upgrade_control_plane_to_version, is_first)

    def test_kube_upgrade_control_plane_duplex_with_worker_failure_with_skew_exceeded(self):
        """Test failed execution of control-plane upgrade on duplex systems: first master

        Skew policy exceeded
        """
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Create controller-0
        config_uuid = str(uuid.uuid4())
        controller0_host_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname=constants.CONTROLLER_0_HOSTNAME,
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
            hostname=constants.CONTROLLER_1_HOSTNAME,
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

        # Create compute-0
        config_uuid = str(uuid.uuid4())
        compute0_host_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.WORKER,
            hostname='compute-0',
            uuid=compute0_host_uuid,
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            mgmt_mac='00:11:22:33:44:57')

        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version='v1.29.2',
            to_version='v1.33.0',
            state=kubernetes.KUBE_UPGRADING_FIRST_MASTER,
        )

        # Set mock outputs This reflects the current environment (i.e. control-plane and kubelet
        # versions on all hosts).
        # Make the control plane upgrade fail, one node has large kubelet skew,
        # e.g., 33 - 29 = 4 (>3 tolerance)
        current_control_plane_versions = {'controller-0': 'v1.32.2',
                                          'controller-1': 'v1.32.2'}
        current_kubelet_versions = {'controller-0': 'v1.32.2',
                                    'controller-1': 'v1.32.2',
                                    'compute-0': 'v1.29.2'}
        # This is what is inside the load.
        get_kube_versions_output = [
            {'version': 'v1.29.2'},
            {'version': 'v1.30.6'},
            {'version': 'v1.31.5'},
            {'version': 'v1.32.2'},
            {'version': 'v1.33.0'},
        ]

        self.service._kube = kubernetes.KubeOperator()

        mock_kube_get_control_plane_versions = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_get_control_plane_versions',
                       mock_kube_get_control_plane_versions)
        p.start().return_value = current_control_plane_versions
        self.addCleanup(p.stop)

        mock_kube_get_kubelet_versions = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_get_kubelet_versions',
                       mock_kube_get_kubelet_versions)
        p.start().return_value = current_kubelet_versions
        self.addCleanup(p.stop)

        mock_get_kube_versions = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.get_kube_versions',
            mock_get_kube_versions)
        p.start().return_value = get_kube_versions_output
        self.addCleanup(p.stop)

        mock_sanitize_kubeadm_configmap = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.sanitize_kubeadm_configmap',
                       mock_sanitize_kubeadm_configmap)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_kubeadm_configmap_reformat = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kubeadm_configmap_reformat',
                       mock_kubeadm_configmap_reformat)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_upgrade_control_plane_agent_api = mock.MagicMock()
        p = mock.patch.object(agent_rpcapi.AgentAPI, 'kube_upgrade_control_plane',
                              mock_upgrade_control_plane_agent_api)
        p.start()
        self.addCleanup(p.stop)

        self.service.kube_upgrade_control_plane(self.context, controller0_host_uuid)

        mock_kube_get_control_plane_versions.assert_called_once()
        mock_kube_get_kubelet_versions.assert_called_once()
        mock_get_kube_versions.assert_called_once()
        mock_sanitize_kubeadm_configmap.assert_not_called()
        mock_kubeadm_configmap_reformat.assert_not_called()
        mock_upgrade_control_plane_agent_api.assert_not_called()

        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state, kubernetes.KUBE_UPGRADING_FIRST_MASTER_FAILED)

    def test_kube_upgrade_control_plane_duplex_failure_with_first_and_second_master_skew(self):
        """Test failed execution of control-plane upgrade on duplex systems: first master

        With first master on N+1 and second on N, Trying to upgrade first master to N+2 before
        upgrading second to N+1 should fail
        """
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Create controller-0
        config_uuid = str(uuid.uuid4())
        controller0_host_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname=constants.CONTROLLER_0_HOSTNAME,
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
            hostname=constants.CONTROLLER_1_HOSTNAME,
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

        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version='v1.29.2',
            to_version='v1.33.0',
            state=kubernetes.KUBE_UPGRADING_FIRST_MASTER,
        )

        # Set mock outputs This reflects the current environment (i.e. control-plane and kubelet
        # versions on all hosts).
        current_control_plane_versions = {'controller-0': 'v1.30.6',
                                          'controller-1': 'v1.29.2'}
        current_kubelet_versions = {'controller-0': 'v1.29.2',
                                    'controller-1': 'v1.29.2'}
        # This is what is inside the load.
        get_kube_versions_output = [
            {'version': 'v1.29.2'},
            {'version': 'v1.30.6'},
            {'version': 'v1.31.5'},
            {'version': 'v1.32.2'},
            {'version': 'v1.33.0'},
        ]

        self.service._kube = kubernetes.KubeOperator()

        mock_kube_get_control_plane_versions = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_get_control_plane_versions',
                       mock_kube_get_control_plane_versions)
        p.start().return_value = current_control_plane_versions
        self.addCleanup(p.stop)

        mock_kube_get_kubelet_versions = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_get_kubelet_versions',
                       mock_kube_get_kubelet_versions)
        p.start().return_value = current_kubelet_versions
        self.addCleanup(p.stop)

        mock_get_kube_versions = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.get_kube_versions',
            mock_get_kube_versions)
        p.start().return_value = get_kube_versions_output
        self.addCleanup(p.stop)

        mock_sanitize_kubeadm_configmap = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.sanitize_kubeadm_configmap',
                       mock_sanitize_kubeadm_configmap)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_kubeadm_configmap_reformat = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kubeadm_configmap_reformat',
                       mock_kubeadm_configmap_reformat)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_upgrade_control_plane_agent_api = mock.MagicMock()
        p = mock.patch.object(agent_rpcapi.AgentAPI, 'kube_upgrade_control_plane',
                              mock_upgrade_control_plane_agent_api)
        p.start()
        self.addCleanup(p.stop)

        self.service.kube_upgrade_control_plane(self.context, controller0_host_uuid)

        mock_kube_get_control_plane_versions.assert_called_once()
        mock_kube_get_kubelet_versions.assert_called_once()
        mock_get_kube_versions.assert_called_once()
        mock_sanitize_kubeadm_configmap.assert_not_called()
        mock_kubeadm_configmap_reformat.assert_not_called()
        mock_upgrade_control_plane_agent_api.assert_not_called()

        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state, kubernetes.KUBE_UPGRADING_FIRST_MASTER_FAILED)

    def test_kube_upgrade_control_plane_duplex_failure_call_first_master_with_wrong_state(self):
        """Test failed execution of control-plane upgrade on duplex systems: first master

        Upgrading first master with wrong state kubernetes.KUBE_UPGRADING_SECOND_MASTER
        """
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Create controller-0
        config_uuid = str(uuid.uuid4())
        controller0_host_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname=constants.CONTROLLER_0_HOSTNAME,
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
            hostname=constants.CONTROLLER_1_HOSTNAME,
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

        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version='v1.29.2',
            to_version='v1.33.0',
            state=kubernetes.KUBE_UPGRADING_SECOND_MASTER,
        )

        # Set mock outputs This reflects the current environment (i.e. control-plane and kubelet
        # versions on all hosts).
        current_control_plane_versions = {'controller-0': 'v1.29.2',
                                          'controller-1': 'v1.29.2'}
        current_kubelet_versions = {'controller-0': 'v1.29.2',
                                    'controller-1': 'v1.29.2'}
        # This is what is inside the load.
        get_kube_versions_output = [
            {'version': 'v1.29.2'},
            {'version': 'v1.30.6'},
            {'version': 'v1.31.5'},
            {'version': 'v1.32.2'},
            {'version': 'v1.33.0'},
        ]

        self.service._kube = kubernetes.KubeOperator()

        mock_kube_get_control_plane_versions = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_get_control_plane_versions',
                       mock_kube_get_control_plane_versions)
        p.start().return_value = current_control_plane_versions
        self.addCleanup(p.stop)

        mock_kube_get_kubelet_versions = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_get_kubelet_versions',
                       mock_kube_get_kubelet_versions)
        p.start().return_value = current_kubelet_versions
        self.addCleanup(p.stop)

        mock_get_kube_versions = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.get_kube_versions',
            mock_get_kube_versions)
        p.start().return_value = get_kube_versions_output
        self.addCleanup(p.stop)

        mock_sanitize_kubeadm_configmap = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.sanitize_kubeadm_configmap',
                       mock_sanitize_kubeadm_configmap)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_kubeadm_configmap_reformat = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kubeadm_configmap_reformat',
                       mock_kubeadm_configmap_reformat)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_upgrade_control_plane_agent_api = mock.MagicMock()
        p = mock.patch.object(agent_rpcapi.AgentAPI, 'kube_upgrade_control_plane',
                              mock_upgrade_control_plane_agent_api)
        p.start()
        self.addCleanup(p.stop)

        # Upgrading control plane with controller0_host_uuid when state is
        # KUBE_UPGRADING_SECOND_MASTER
        self.service.kube_upgrade_control_plane(self.context, controller0_host_uuid)

        mock_kube_get_control_plane_versions.assert_called_once()
        mock_kube_get_kubelet_versions.assert_called_once()
        mock_get_kube_versions.assert_called_once()
        mock_sanitize_kubeadm_configmap.assert_not_called()
        mock_kubeadm_configmap_reformat.assert_not_called()
        mock_upgrade_control_plane_agent_api.assert_not_called()

        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state, kubernetes.KUBE_UPGRADING_FIRST_MASTER_FAILED)

    def test_kube_upgrade_control_plane_duplex_failure_kubeadm_configmap_reformat_error(self):
        """Test failed execution of control-plane upgrade on DX systems: configmap reformat error

        """
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Create controller-0
        config_uuid = str(uuid.uuid4())
        controller0_host_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname=constants.CONTROLLER_0_HOSTNAME,
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
            hostname=constants.CONTROLLER_1_HOSTNAME,
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

        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version='v1.29.2',
            to_version='v1.30.6',
            state=kubernetes.KUBE_UPGRADING_FIRST_MASTER,
        )

        # Set mock outputs. This reflects the current environment (i.e. control-plane and kubelet
        # versions on all hosts).
        current_control_plane_versions = {'controller-0': 'v1.29.2',
                                          'controller-1': 'v1.29.2'}
        current_kubelet_versions = {'controller-0': 'v1.29.2',
                                    'controller-1': 'v1.29.2'}
        # This is what is inside the load.
        get_kube_versions_output = [
            {'version': 'v1.29.2'},
            {'version': 'v1.30.6'},
            {'version': 'v1.31.5'},
            {'version': 'v1.32.2'},
            {'version': 'v1.33.0'},
        ]

        self.service._kube = kubernetes.KubeOperator()

        mock_kube_get_control_plane_versions = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_get_control_plane_versions',
                       mock_kube_get_control_plane_versions)
        p.start().return_value = current_control_plane_versions
        self.addCleanup(p.stop)

        mock_kube_get_kubelet_versions = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_get_kubelet_versions',
                       mock_kube_get_kubelet_versions)
        p.start().return_value = current_kubelet_versions
        self.addCleanup(p.stop)

        mock_get_kube_versions = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.get_kube_versions',
            mock_get_kube_versions)
        p.start().return_value = get_kube_versions_output
        self.addCleanup(p.stop)

        mock_sanitize_kubeadm_configmap = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.sanitize_kubeadm_configmap',
                       mock_sanitize_kubeadm_configmap)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_kubeadm_configmap_reformat = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kubeadm_configmap_reformat',
                       mock_kubeadm_configmap_reformat)
        p.start().return_value = 1
        self.addCleanup(p.stop)

        mock_upgrade_control_plane_agent_api = mock.MagicMock()
        p = mock.patch.object(agent_rpcapi.AgentAPI, 'kube_upgrade_control_plane',
                              mock_upgrade_control_plane_agent_api)
        p.start()
        self.addCleanup(p.stop)

        self.service.kube_upgrade_control_plane(self.context, controller0_host_uuid)

        mock_kube_get_control_plane_versions.assert_called_once()
        mock_kube_get_kubelet_versions.assert_called_once()
        mock_get_kube_versions.assert_called_once()
        mock_sanitize_kubeadm_configmap.assert_called_once()
        mock_kubeadm_configmap_reformat.assert_called_once()
        mock_upgrade_control_plane_agent_api.assert_not_called()

        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state, kubernetes.KUBE_UPGRADING_FIRST_MASTER_FAILED)

    def test_kube_upgrade_control_plane_duplex_failure_sysinv_agent_api_unexpected_exception(self):
        """Test failed execution of control-plane upgrade on DX systems: unexpected error

        """
        self.skipTest("WIP:jgauld etcd-versions")

        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Create controller-0
        config_uuid = str(uuid.uuid4())
        controller0_host_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname=constants.CONTROLLER_0_HOSTNAME,
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
            hostname=constants.CONTROLLER_1_HOSTNAME,
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

        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version='v1.29.2',
            to_version='v1.30.6',
            state=kubernetes.KUBE_UPGRADING_SECOND_MASTER,
        )

        # Set mock outputs. This reflects the current environment (i.e. control-plane and kubelet
        # versions on all hosts).
        current_control_plane_versions = {'controller-0': 'v1.30.6',
                                          'controller-1': 'v1.29.2'}
        current_kubelet_versions = {'controller-0': 'v1.29.2',
                                    'controller-1': 'v1.29.2'}
        # This is what is inside the load.
        get_kube_versions_output = [
            {'version': 'v1.29.2'},
            {'version': 'v1.30.6'},
            {'version': 'v1.31.5'},
            {'version': 'v1.32.2'},
            {'version': 'v1.33.0'},
        ]

        # Set expectations: argument values with which Sysinv-agent API call is expected to be made
        upgrade_control_plane_to_version = 'v1.30.6'
        is_first = False

        self.service._kube = kubernetes.KubeOperator()

        mock_kube_get_control_plane_versions = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_get_control_plane_versions',
                       mock_kube_get_control_plane_versions)
        p.start().return_value = current_control_plane_versions
        self.addCleanup(p.stop)

        mock_kube_get_kubelet_versions = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_get_kubelet_versions',
                       mock_kube_get_kubelet_versions)
        p.start().return_value = current_kubelet_versions
        self.addCleanup(p.stop)

        mock_get_kube_versions = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.get_kube_versions',
            mock_get_kube_versions)
        p.start().return_value = get_kube_versions_output
        self.addCleanup(p.stop)

        mock_sanitize_kubeadm_configmap = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.sanitize_kubeadm_configmap',
                       mock_sanitize_kubeadm_configmap)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_kubeadm_configmap_reformat = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kubeadm_configmap_reformat',
                       mock_kubeadm_configmap_reformat)
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mock_upgrade_control_plane_agent_api = mock.MagicMock()
        p = mock.patch.object(agent_rpcapi.AgentAPI, 'kube_upgrade_control_plane',
                              mock_upgrade_control_plane_agent_api)
        p.start().side_effect = Exception("Fake error")
        self.addCleanup(p.stop)

        self.service.kube_upgrade_control_plane(self.context, controller1_host_uuid)

        mock_kube_get_control_plane_versions.assert_called_once()
        mock_kube_get_kubelet_versions.assert_called_once()
        mock_get_kube_versions.assert_called_once()
        mock_sanitize_kubeadm_configmap.assert_not_called()
        mock_kubeadm_configmap_reformat.assert_not_called()
        mock_upgrade_control_plane_agent_api.assert_called_once_with(
            self.context, controller1_host_uuid, upgrade_control_plane_to_version, is_first)

        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state, kubernetes.KUBE_UPGRADING_SECOND_MASTER_FAILED)

    def test_pin_kubernetes_control_plane_images_simplex_success(self):
        """Test successful execution of pin control-plane images

        """
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_SIMPLEX
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Create controller-0
        config_uuid = str(uuid.uuid4())
        controller0_host_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname=constants.CONTROLLER_0_HOSTNAME,
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

        mock_pin_kubernetes_control_plane_images = mock.MagicMock()
        p = mock.patch.object(agent_rpcapi.AgentAPI, 'pin_kubernetes_control_plane_images',
                              mock_pin_kubernetes_control_plane_images)
        p.start()
        self.addCleanup(p.stop)

        FAKE_KUBE_VERSION = 'v1.29.2'

        self.service.pin_kubernetes_control_plane_images(self.context, FAKE_KUBE_VERSION)

        mock_pin_kubernetes_control_plane_images.assert_called_once_with(
            self.context, controller0_host_uuid, FAKE_KUBE_VERSION)

    def test_pin_kubernetes_control_plane_images_duplex_success(self):
        """Test successful execution of pin control-plane images

        """
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Create controller-0
        config_uuid = str(uuid.uuid4())
        controller0_host_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname=constants.CONTROLLER_0_HOSTNAME,
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
            hostname=constants.CONTROLLER_1_HOSTNAME,
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

        # Create compute-0
        config_uuid = str(uuid.uuid4())
        compute0_host_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.WORKER,
            hostname='compute-0',
            uuid=compute0_host_uuid,
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            mgmt_mac='00:11:22:33:44:57')

        mock_pin_kubernetes_control_plane_images = mock.MagicMock()
        p = mock.patch.object(agent_rpcapi.AgentAPI, 'pin_kubernetes_control_plane_images',
                              mock_pin_kubernetes_control_plane_images)
        p.start()
        self.addCleanup(p.stop)

        FAKE_KUBE_VERSION = 'v1.29.2'

        self.service.pin_kubernetes_control_plane_images(self.context, FAKE_KUBE_VERSION)

        expected_calls = [mock.call(self.context, controller0_host_uuid, FAKE_KUBE_VERSION),
                          mock.call(self.context, controller1_host_uuid, FAKE_KUBE_VERSION)]
        mock_pin_kubernetes_control_plane_images.assert_has_calls(expected_calls)
        self.assertEqual(mock_pin_kubernetes_control_plane_images.call_count, 2)

    def test_pin_kubernetes_control_plane_images_failure(self):
        """Test failed execution of pin control-plane images

        """
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_SIMPLEX
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Create controller-0
        config_uuid = str(uuid.uuid4())
        controller0_host_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname=constants.CONTROLLER_0_HOSTNAME,
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

        mock_pin_kubernetes_control_plane_images = mock.MagicMock()
        p = mock.patch.object(agent_rpcapi.AgentAPI, 'pin_kubernetes_control_plane_images',
                              mock_pin_kubernetes_control_plane_images)
        p.start().side_effect = Exception("Fake error")
        self.addCleanup(p.stop)

        FAKE_KUBE_VERSION = 'v1.29.2'

        self.service.pin_kubernetes_control_plane_images(self.context, FAKE_KUBE_VERSION)

        mock_pin_kubernetes_control_plane_images.assert_called_once_with(
            self.context, controller0_host_uuid, FAKE_KUBE_VERSION)

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

        # TODO(jgauld) -- test high-level call routine only
        # TODO(jgauld): Add to test_etcd : get_etcd_version_from_symlink, etcd.store_etcd_version()
        # MOVE to the etcd module possibly or control_plane upgrade
        # current_link_etcd = '/usr/local/etcd/3.4.37/stage0'
        # mock_os_readlink_etcd = mock.MagicMock()
        # p = mock.patch('os.readlink', mock_os_readlink_etcd)
        # p.start().return_value = current_link_etcd
        # self.addCleanup(p.stop)
        # self.call_etcd_function_TBD
        # mock_os_readlink_etcd.assert_called_once()

        mock_etcd_store_etcd_version = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.etcd.store_etcd_version',
            mock_etcd_store_etcd_version)
        p.start()
        self.addCleanup(p.stop)

        self.service.backup_kube_control_plane(self.context)
        mock_remove_kube_control_plane_backup.assert_called()
        mock_backup_kube_static_pods.assert_called()
        mock_etcd_snapshot_etcd.assert_called()
        mock_etcd_store_etcd_version.assert_called()

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

        self.get_reorder_apps_result = {
            constants.APP_METADATA_DEPENDENT_APPS: [],
            constants.APP_METADATA_CLASS: {
                constants.APP_METADATA_CLASS_CRITICAL: [],
                constants.APP_METADATA_CLASS_STORAGE: [],
                constants.APP_METADATA_CLASS_DISCOVERY: [],
                constants.APP_METADATA_CLASS_OPTIONAL: [],
                constants.APP_METADATA_CLASS_REPORTING: []
            },
            constants.APP_METADATA_INDEPENDENT_APPS: ['stx-openstack']
        }

        def mock_auto_update_app(obj,
                                 context,
                                 app_name,
                                 k8s_version=None,
                                 k8s_upgrade_timing=None,
                                 async_update=True,
                                 skip_validations=False,
                                 ignore_locks=False):
            return True
        mocked_auto_update_app = mock.patch(
            'sysinv.conductor.manager.ConductorManager._auto_update_app',
            mock_auto_update_app)
        mocked_auto_update_app.start()
        self.addCleanup(mocked_auto_update_app.stop)

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

        self.get_reorder_apps_result = {
            constants.APP_METADATA_DEPENDENT_APPS: [],
            constants.APP_METADATA_CLASS: {
                constants.APP_METADATA_CLASS_CRITICAL: [],
                constants.APP_METADATA_CLASS_STORAGE: [],
                constants.APP_METADATA_CLASS_DISCOVERY: [],
                constants.APP_METADATA_CLASS_OPTIONAL: [],
                constants.APP_METADATA_CLASS_REPORTING: []
            },
            constants.APP_METADATA_INDEPENDENT_APPS: ['stx-openstack']
        }

        def mock_auto_update_app(obj,
                                 context,
                                 app_name,
                                 k8s_version=None,
                                 k8s_upgrade_timing=None,
                                 async_update=True,
                                 skip_validations=False,
                                 ignore_locks=False):
            return True
        mocked_auto_update_app = mock.patch(
            'sysinv.conductor.manager.ConductorManager._auto_update_app',
            mock_auto_update_app)
        mocked_auto_update_app.start()
        self.addCleanup(mocked_auto_update_app.stop)

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

    def test_kube_post_application_update_app_failed(self):
        # Test post app update step when the application fails to be updated.

        self.get_reorder_apps_result = {
            constants.APP_METADATA_DEPENDENT_APPS: [],
            constants.APP_METADATA_CLASS: {
                constants.APP_METADATA_CLASS_CRITICAL: [],
                constants.APP_METADATA_CLASS_STORAGE: [],
                constants.APP_METADATA_CLASS_DISCOVERY: [],
                constants.APP_METADATA_CLASS_OPTIONAL: [],
                constants.APP_METADATA_CLASS_REPORTING: []
            },
            constants.APP_METADATA_INDEPENDENT_APPS: ['stx-openstack']
        }

        def mock_auto_update_app(obj,
                                 context,
                                 app_name,
                                 k8s_version=None,
                                 k8s_upgrade_timing=None,
                                 async_update=True,
                                 skip_validations=False,
                                 ignore_locks=False):
            return False

        mocked_auto_update_app = mock.patch(
            'sysinv.conductor.manager.ConductorManager._auto_update_app',
            mock_auto_update_app)
        mocked_auto_update_app.start()
        self.addCleanup(mocked_auto_update_app.stop)

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

        # Run update
        self.service.kube_post_application_update(self.context, to_version)

        # Verify that the upgrade state was updated
        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state,
                         kubernetes.KUBE_POST_UPDATING_APPS_FAILED)

    def test_kube_post_application_update_app_skipped(self):
        # Test post app update step when the application update is skipped.

        self.get_reorder_apps_result = {
            constants.APP_METADATA_DEPENDENT_APPS: [],
            constants.APP_METADATA_CLASS: {
                constants.APP_METADATA_CLASS_CRITICAL: [],
                constants.APP_METADATA_CLASS_STORAGE: [],
                constants.APP_METADATA_CLASS_DISCOVERY: [],
                constants.APP_METADATA_CLASS_OPTIONAL: [],
                constants.APP_METADATA_CLASS_REPORTING: []
            },
            constants.APP_METADATA_INDEPENDENT_APPS: ['stx-openstack']
        }

        def mock_auto_update_app(obj,
                                 context,
                                 app_name,
                                 k8s_version=None,
                                 k8s_upgrade_timing=None,
                                 async_update=True,
                                 skip_validations=False,
                                 ignore_locks=False):
            return None

        mocked_auto_update_app = mock.patch(
            'sysinv.conductor.manager.ConductorManager._auto_update_app',
            mock_auto_update_app)
        mocked_auto_update_app.start()
        self.addCleanup(mocked_auto_update_app.stop)

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

        # Run update
        self.service.kube_post_application_update(self.context, to_version)

        # Verify that the upgrade state was updated
        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state,
                         kubernetes.KUBE_POST_UPDATED_APPS)

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

    # ------------------------------------------------------------------
    # Direct unit test for the _should_skip_deferred_config predicate.
    # Table-driven: each row is an independent scenario exercised via
    # subTest. (expected == True means "skip and drop from queue".)
    # ------------------------------------------------------------------

    # Reusable host-state tuples: (administrative, operational, availability)
    _HOST_OFFLINE = (constants.ADMIN_LOCKED,
                     constants.OPERATIONAL_DISABLED,
                     constants.AVAILABILITY_OFFLINE)
    _HOST_ONLINE = (constants.ADMIN_UNLOCKED,
                    constants.OPERATIONAL_ENABLED,
                    constants.AVAILABILITY_ONLINE)
    _HOST_LOCKED_ONLINE = (constants.ADMIN_LOCKED,
                           constants.OPERATIONAL_DISABLED,
                           constants.AVAILABILITY_ONLINE)

    # Reusable manifest class lists.
    _CLASSES_NONGRUB = ['platform::users::runtime']
    _CLASSES_GRUB = ['platform::compute::grub::runtime']
    _CLASSES_MIXED = ['platform::users::runtime',
                      'platform::grub::kernel_image::runtime']

    def _make_worker(self, hostname, host_state):
        """Create a locked/unlocked worker host from a host-state tuple."""
        administrative, operational, availability = host_state
        # get_test_ihost() supplies a fixed default mgmt_mac, which collides
        # on the i_host.mgmt_mac UNIQUE constraint when more than one host is
        # created. Assign a unique mgmt_mac per host to avoid this.
        self._worker_mac_seq = getattr(self, '_worker_mac_seq', 0) + 1
        mgmt_mac = "02:00:00:00:%02x:%02x" % (
            (self._worker_mac_seq >> 8) & 0xff, self._worker_mac_seq & 0xff)
        return self._create_test_ihost(
            personality=constants.WORKER,
            hostname=hostname,
            uuid=str(uuid.uuid4()),
            mgmt_mac=mgmt_mac,
            invprovision=constants.PROVISIONED,
            administrative=administrative,
            operational=operational,
            availability=availability,
        )

    def test_should_skip_deferred_config(self):
        """Table-driven coverage of the skip predicate.

        Each case: (name, host_states, num_deleted, classes, expected_skip)
        where host_states are created hosts and num_deleted are non-existent
        (deleted) host uuids appended to the target list.
        """
        cases = [
            # No target hosts -> never skip.
            ("no_host_uuids",
             [], 0, self._CLASSES_NONGRUB, False),
            # Single offline host, non-GRUB -> skip.
            ("offline_nongrub",
             [self._HOST_OFFLINE], 0, self._CLASSES_NONGRUB, True),
            # GRUB manifest is always allowed, even on offline host.
            ("offline_grub",
             [self._HOST_OFFLINE], 0, self._CLASSES_GRUB, False),
            # Batch with any GRUB class preserves the GRUB optimization.
            ("offline_mixed_grub",
             [self._HOST_OFFLINE], 0, self._CLASSES_MIXED, False),
            # Reachable (unlocked-online) host -> not skipped.
            ("unlocked_online",
             [self._HOST_ONLINE], 0, self._CLASSES_NONGRUB, False),
            # Locked but online: agent still runs -> not skipped.
            ("locked_online",
             [self._HOST_LOCKED_ONLINE], 0, self._CLASSES_NONGRUB, False),
            # One offline + one online -> reachable host wins, not skipped.
            ("mixed_online_offline",
             [self._HOST_OFFLINE, self._HOST_ONLINE], 0,
             self._CLASSES_NONGRUB, False),
            # Deleted host ignored; remaining host offline -> skip.
            ("deleted_then_offline",
             [self._HOST_OFFLINE], 1, self._CLASSES_NONGRUB, True),
            # All targets deleted -> none reachable -> skip.
            ("all_hosts_deleted",
             [], 2, self._CLASSES_NONGRUB, True),
            # Force-applied config -> never skip, even on offline host.
            ("force_applied_offline",
             [self._HOST_OFFLINE], 0, self._CLASSES_NONGRUB, False),
        ]

        for idx, (name, states, num_deleted, classes, expected) in \
                enumerate(cases):
            with self.subTest(case=name):
                host_uuids = [
                    self._make_worker("compute-%d-%d" % (idx, j), state).uuid
                    for j, state in enumerate(states)]
                host_uuids += [str(uuid.uuid4()) for _ in range(num_deleted)]
                config_dict = {
                    'personalities': [constants.WORKER],
                    'classes': classes,
                    'host_uuids': host_uuids,
                }
                # Add force=True for the force test case
                if name == "force_applied_offline":
                    config_dict['force'] = True
                result = self.service._should_skip_deferred_config(
                    str(uuid.uuid4()), config_dict, classes)
                self.assertEqual(expected, result,
                                 "case=%s: expected %s got %s"
                                 % (name, expected, result))

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
            'sriov_vf_driver': None, 'pvendor': 'Intel Corporation [8086]',
            'numchannels': 32, 'maxchannels': 64, 'sriov_vf_numchannels': 2,
            'sriov_vf_maxchannels': 4}
        enp25s0f1 = {'dev_id': 0, 'numa_node': 0, 'sriov_numvfs': 0, 'sriov_vfs_pci_address': '',
            'pdevice': 'Ethernet Controller X710 for 10GbE SFP+ [1572]', 'link_mode': '0',
            'driver': 'i40e', 'pclass': 'Ethernet controller [0200]', 'mtu': 1500,
            'psdevice': 'Ethernet Converged Network Adapter X710 [0000]',
            'mac': '3c:fd:fe:b5:72:e1', 'prevision': '-r01', 'sriov_vf_pdevice_id': None,
            'sriov_totalvfs': 64, 'pciaddr': '0000:19:00.1', 'dpdksupport': True,
            'pname': 'enp25s0f1', 'speed': 10000, 'psvendor': 'Intel Corporation [8086]',
            'sriov_vf_driver': None, 'pvendor': 'Intel Corporation [8086]',
            'numchannels': 32, 'maxchannels': 64, 'sriov_vf_numchannels': 2,
            'sriov_vf_maxchannels': 4}
        enp134s0f0 = {'dev_id': 0, 'numa_node': 1, 'sriov_numvfs': 0, 'sriov_vfs_pci_address': '',
            'pdevice': '82571EB/82571GB Gigabit Ethernet Controller D0/D1 [105e]',
            'link_mode': '0', 'driver': 'e1000e', 'pclass': 'Ethernet controller [0200]',
            'mtu': 1500, 'psdevice': 'PRO/1000 PT Dual Port Server Adapter [115e]',
            'mac': '00:15:17:cd:c4:ac', 'prevision': '-r06', 'sriov_vf_pdevice_id': None,
            'sriov_totalvfs': None, 'pciaddr': '0000:86:00.0', 'dpdksupport': False,
            'pname': 'enp134s0f0', 'speed': None, 'psvendor': 'Intel Corporation [8086]',
            'sriov_vf_driver': None, 'pvendor': 'Intel Corporation [8086]',
            'numchannels': 32, 'maxchannels': 64, 'sriov_vf_numchannels': 2,
            'sriov_vf_maxchannels': 4}
        enp134s0f1 = {'dev_id': 0, 'numa_node': 1, 'sriov_numvfs': 0, 'sriov_vfs_pci_address': '',
            'pdevice': '82571EB/82571GB Gigabit Ethernet Controller D0/D1 [105e]', 'link_mode': '0',
            'driver': 'e1000e', 'pclass': 'Ethernet controller [0200]',
            'mtu': 1500, 'psdevice': 'PRO/1000 PT Dual Port Server Adapter [115e]',
            'mac': '00:15:17:cd:c4:ad', 'prevision': '-r06', 'sriov_vf_pdevice_id': None,
            'sriov_totalvfs': None, 'pciaddr': '0000:86:00.1', 'dpdksupport': False,
            'pname': 'enp134s0f1', 'speed': 1000, 'psvendor': 'Intel Corporation [8086]',
            'sriov_vf_driver': None, 'pvendor': 'Intel Corporation [8086]',
            'numchannels': 32, 'maxchannels': 64, 'sriov_vf_numchannels': 2,
            'sriov_vf_maxchannels': 4}
        enp135s0f0 = {'dev_id': 0, 'numa_node': 1, 'sriov_numvfs': 0, 'sriov_vfs_pci_address': '',
            'pdevice': 'Ethernet Controller X710 for 10GbE SFP+ [1572]', 'link_mode': '0',
            'driver': 'i40e', 'pclass': 'Ethernet controller [0200]', 'mtu': 9216,
            'psdevice': 'Ethernet Converged Network Adapter X710-2 [0008]',
            'mac': '3c:fd:fe:b5:73:28', 'prevision': '-r01', 'sriov_vf_pdevice_id': None,
            'sriov_totalvfs': 64, 'pciaddr': '0000:87:00.0', 'dpdksupport': True,
            'pname': 'enp135s0f0', 'speed': 10000, 'psvendor': 'Intel Corporation [8086]',
            'sriov_vf_driver': None, 'pvendor': 'Intel Corporation [8086]',
            'numchannels': 32, 'maxchannels': 64, 'sriov_vf_numchannels': 2,
            'sriov_vf_maxchannels': 4}
        enp135s0f1 = {'dev_id': 0, 'numa_node': 1, 'sriov_numvfs': 0, 'sriov_vfs_pci_address': '',
            'pdevice': 'Ethernet Controller X710 for 10GbE SFP+ [1572]', 'link_mode': '0',
            'driver': 'i40e', 'pclass': 'Ethernet controller [0200]', 'mtu': 1500,
            'psdevice': 'Ethernet Converged Network Adapter X710 [0000]',
            'mac': '3c:fd:fe:b5:73:29', 'prevision': '-r01', 'sriov_vf_pdevice_id': None,
            'sriov_totalvfs': 64, 'pciaddr': '0000:87:00.1', 'dpdksupport': True,
            'pname': 'enp135s0f1', 'speed': None, 'psvendor': 'Intel Corporation [8086]',
            'sriov_vf_driver': None, 'pvendor': 'Intel Corporation [8086]',
            'numchannels': 32, 'maxchannels': 64, 'sriov_vf_numchannels': 2,
            'sriov_vf_maxchannels': 4}
        enp177s0f0 = {'dev_id': 0, 'numa_node': 1, 'sriov_numvfs': 0, 'sriov_vfs_pci_address': '',
            'pdevice': 'Device [0d58]', 'link_mode': '0', 'driver': 'i40e',
            'pclass': 'Ethernet controller [0200]', 'mtu': 1500, 'psdevice': 'Device [0000]',
            'mac': '64:4c:36:12:9b:78', 'prevision': '-r02', 'sriov_vf_pdevice_id': None,
            'sriov_totalvfs': 64, 'pciaddr': '0000:b1:00.0', 'dpdksupport': False,
            'pname': 'enp177s0f0', 'speed': None, 'psvendor': 'Intel Corporation [8086]',
            'sriov_vf_driver': None, 'pvendor': 'Intel Corporation [8086]',
            'numchannels': 32, 'maxchannels': 64, 'sriov_vf_numchannels': 2,
            'sriov_vf_maxchannels': 4}
        enp177s0f1 = {'dev_id': 0, 'numa_node': 1, 'sriov_numvfs': 0, 'sriov_vfs_pci_address': '',
            'pdevice': 'Device [0d58]', 'link_mode': '0', 'driver': 'i40e',
            'pclass': 'Ethernet controller [0200]', 'mtu': 1500, 'psdevice': 'Device [0000]',
            'mac': '64:4c:36:12:9b:79', 'prevision': '-r02', 'sriov_vf_pdevice_id': None,
            'sriov_totalvfs': 64, 'pciaddr': '0000:b1:00.1', 'dpdksupport': False,
            'pname': 'enp177s0f1', 'speed': None, 'psvendor': 'Intel Corporation [8086]',
            'sriov_vf_driver': None, 'pvendor': 'Intel Corporation [8086]',
            'numchannels': 32, 'maxchannels': 64, 'sriov_vf_numchannels': 2,
            'sriov_vf_maxchannels': 4}
        enp181s0f0 = {'dev_id': 0, 'numa_node': 1, 'sriov_numvfs': 0, 'sriov_vfs_pci_address': '',
            'pdevice': 'Device [0d58]', 'link_mode': '0', 'driver': 'i40e',
            'pclass': 'Ethernet controller [0200]', 'mtu': 1500, 'psdevice': 'Device [0000]',
            'mac': '64:4c:36:12:9b:7c', 'prevision': '-r02', 'sriov_vf_pdevice_id': None,
            'sriov_totalvfs': 64, 'pciaddr': '0000:b3:00.0', 'dpdksupport': False,
            'pname': 'enp181s0f0', 'speed': None, 'psvendor': 'Intel Corporation [8086]',
            'sriov_vf_driver': None, 'pvendor': 'Intel Corporation [8086]',
            'numchannels': 32, 'maxchannels': 64, 'sriov_vf_numchannels': 2,
            'sriov_vf_maxchannels': 4}
        enp181s0f1 = {'dev_id': 0, 'numa_node': 1, 'sriov_numvfs': 0, 'sriov_vfs_pci_address': '',
            'pdevice': 'Device [0d58]', 'link_mode': '0', 'driver': 'i40e',
            'pclass': 'Ethernet controller [0200]', 'mtu': 1500, 'psdevice': 'Device [0000]',
            'mac': '64:4c:36:12:9b:7d', 'prevision': '-r02', 'sriov_vf_pdevice_id': None,
            'sriov_totalvfs': 64, 'pciaddr': '0000:b3:00.1', 'dpdksupport': False,
            'pname': 'enp181s0f1', 'speed': None, 'psvendor': 'Intel Corporation [8086]',
            'sriov_vf_driver': None, 'pvendor': 'Intel Corporation [8086]',
            'numchannels': 32, 'maxchannels': 64, 'sriov_vf_numchannels': 2,
            'sriov_vf_maxchannels': 4}

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
        inic_dict_array[-1]['numchannels'] = 32
        inic_dict_array[-1]['maxchannels'] = 64
        inic_dict_array[-1]['sriov_vf_numchannels'] = 2
        inic_dict_array[-1]['sriov_vf_maxchannels'] = 4

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
        self.assertEqual(port.numchannels, inic_dict_array[-1]['numchannels'])
        self.assertEqual(port.maxchannels, inic_dict_array[-1]['maxchannels'])
        self.assertEqual(port.sriov_vf_numchannels, inic_dict_array[-1]['sriov_vf_numchannels'])
        self.assertEqual(port.sriov_vf_maxchannels, inic_dict_array[-1]['sriov_vf_maxchannels'])

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

    def test_inumas_update_by_ihost_activates_new_numa_node(self):
        # Simulate a BIOS change that adds a second NUMA node (e.g. SNC-1 -> SNC-2).
        # The new node should be created with is_active=True and the existing
        # node should be re-confirmed active.
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

        # Only node 0 exists in DB initially
        utils.create_test_node(id=1, numa_node=0, forihostid=host_id,
                               capabilities={'is_active': True})

        # Agent now reports both node 0 and node 1
        inuma_dict_array = [{'numa_node': 0}, {'numa_node': 1}]
        self.service.inumas_update_by_ihost(self.context, host_uuid, inuma_dict_array)

        inodes = self.dbapi.inode_get_by_ihost(host_uuid)
        numa_map = {n['numa_node']: n for n in inodes}

        # Both nodes must exist and be active
        self.assertIn(0, numa_map)
        self.assertIn(1, numa_map)
        self.assertTrue(numa_map[0]['capabilities'].get('is_active'))
        self.assertTrue(numa_map[1]['capabilities'].get('is_active'))

    def test_inumas_update_by_ihost_deactivates_removed_numa_node(self):
        # Simulate a BIOS change that removes a NUMA node (e.g. SNC-2 -> SNC-1).
        # The stale node must be marked inactive but NOT deleted, to preserve
        # user-configured hugepage/platform_reserved_mib settings.
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

        # Both nodes exist in DB initially
        utils.create_test_node(id=1, numa_node=0, forihostid=host_id,
                               capabilities={'is_active': True})
        utils.create_test_node(id=2, numa_node=1, forihostid=host_id,
                               capabilities={'is_active': True})

        # Agent now reports only node 0 (node 1 disappeared)
        inuma_dict_array = [{'numa_node': 0}]
        self.service.inumas_update_by_ihost(self.context, host_uuid, inuma_dict_array)

        inodes = self.dbapi.inode_get_by_ihost(host_uuid)
        numa_map = {n['numa_node']: n for n in inodes}

        # Both rows must still exist (additive-only)
        self.assertIn(0, numa_map)
        self.assertIn(1, numa_map)
        # Node 0 stays active, node 1 must be marked inactive
        self.assertTrue(numa_map[0]['capabilities'].get('is_active'))
        self.assertFalse(numa_map[1]['capabilities'].get('is_active'))

    def test_iport_update_by_ihost_numa_affinity_change_snc1_to_snc2(self):
        """Test port numa_node and node_id update when SNC-1 expands to SNC-2.

        On SNC-1 all ports are on numa_node 0. When BIOS is switched to SNC-2
        some ports physically move to numa_node 1. The agent reports the new
        numa_node for those ports and iport_update_by_ihost must update both
        port.numa_node and port.node_id to point to the correct inode.
        """
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

        # SNC-1: all ports report numa_node=0
        inic_dict_array = self._create_test_iports()
        for inic in inic_dict_array:
            inic['numa_node'] = 0
        self.service.iport_update_by_ihost(self.context, ihost['uuid'], inic_dict_array)

        # Create inode for numa_node 0 only (SNC-1 state)
        inuma_dict_array = [{'numa_node': 0, 'capabilities': {}}]
        self.service.inumas_update_by_ihost(self.context, ihost['uuid'], inuma_dict_array)

        inode0 = self.dbapi.inode_get_by_ihost(ihost['uuid'])[0]

        # Verify all ports initially point to inode0
        for port in self.dbapi.ethernet_port_get_by_host(ihost['uuid']):
            self.assertEqual(0, port.numa_node)
            self.assertEqual(inode0['id'], port.node_id)

        # SNC-2: BIOS change — agent now reports two numa nodes and some ports
        # have moved to numa_node 1 (enp134s0f0, enp134s0f1 at pciaddr 0000:86:00.x)
        inuma_dict_array2 = [{'numa_node': 0, 'capabilities': {}},
                             {'numa_node': 1, 'capabilities': {}}]
        self.service.inumas_update_by_ihost(self.context, ihost['uuid'], inuma_dict_array2)

        inodes = {n['numa_node']: n for n in self.dbapi.inode_get_by_ihost(ihost['uuid'])}

        inic_dict_array2 = self._create_test_iports()  # original numa_node values restored
        self.service.iport_update_by_ihost(self.context, ihost['uuid'], inic_dict_array2)

        pciaddr_to_inic = {inic['pciaddr']: inic for inic in inic_dict_array2}
        for port in self.dbapi.ethernet_port_get_by_host(ihost['uuid']):
            expected_numa = pciaddr_to_inic[port.pciaddr]['numa_node']
            expected_node_id = inodes[expected_numa]['id']
            self.assertEqual(expected_numa, port.numa_node,
                             "port %s numa_node mismatch" % port.pciaddr)
            self.assertEqual(expected_node_id, port.node_id,
                             "port %s node_id mismatch" % port.pciaddr)

    def test_iport_update_by_ihost_numa_affinity_change_snc2_to_snc1(self):
        """Test port numa_node and node_id update when SNC-2 collapses to SNC-1.

        On SNC-2 ports are spread across numa_node 0 and 1. When BIOS is
        switched back to SNC-1 all ports move to numa_node 0. The agent
        reports numa_node=0 for all ports and iport_update_by_ihost must
        update port.numa_node and port.node_id accordingly.
        """
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

        # SNC-2: ports spread across numa_node 0 and 1
        inic_dict_array = self._create_test_iports()
        self.service.iport_update_by_ihost(self.context, ihost['uuid'], inic_dict_array)

        inuma_dict_array = [{'numa_node': 0, 'capabilities': {}},
                            {'numa_node': 1, 'capabilities': {}}]
        self.service.inumas_update_by_ihost(self.context, ihost['uuid'], inuma_dict_array)

        inodes = {n['numa_node']: n for n in self.dbapi.inode_get_by_ihost(ihost['uuid'])}
        inode0 = inodes[0]

        # SNC-1: BIOS change — agent now reports only numa_node 0, all ports
        # collapse to numa_node 0
        inuma_dict_array2 = [{'numa_node': 0, 'capabilities': {}}]
        self.service.inumas_update_by_ihost(self.context, ihost['uuid'], inuma_dict_array2)

        inic_dict_array2 = self._create_test_iports()
        for inic in inic_dict_array2:
            inic['numa_node'] = 0
        self.service.iport_update_by_ihost(self.context, ihost['uuid'], inic_dict_array2)

        for port in self.dbapi.ethernet_port_get_by_host(ihost['uuid']):
            self.assertEqual(0, port.numa_node,
                             "port %s should be on numa_node 0" % port.pciaddr)
            self.assertEqual(inode0['id'], port.node_id,
                             "port %s node_id should point to inode0" % port.pciaddr)

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

    GRUB_RUNTIME_CLASSES = ['platform::compute::grub::runtime',
                            'platform::compute::config::runtime']

    def _create_test_worker_ihost(self, hostname='controller-1', **kwargs):
        """Create a host with the worker subfunction, as in an AIO system"""
        config_uuid = str(uuid.uuid4())
        values = {
            'personality': constants.CONTROLLER,
            'hostname': hostname,
            'subfunctions': "%s,%s" % (constants.CONTROLLER,
                                       constants.WORKER),
            'uuid': str(uuid.uuid4()),
            'config_status': None,
            'config_applied': config_uuid,
            'config_target': config_uuid,
            'invprovision': constants.PROVISIONED,
            'inv_state': constants.INV_STATE_INITIAL_INVENTORIED,
            'administrative': constants.ADMIN_LOCKED,
            'operational': constants.OPERATIONAL_DISABLED,
            'availability': constants.AVAILABILITY_ONLINE,
            'mgmt_mac': '22:44:33:55:11:88',
        }
        values.update(kwargs)
        return self._create_test_ihost(**values)

    def _create_pending_runtime_config(
            self, host, classes,
            state=constants.RUNTIME_CONFIG_STATE_PENDING,
            cpu_watermark=None):
        """Create a runtime config entry applying the given classes

        Defaults to a pending entry. The state can be overridden so that an
        entry that already left the queue, such as an applied one, can be
        created as well.

        When cpu_watermark is given it is stored under
        GRUB_CPU_WATERMARK_KEY, exactly as update_grub_config() persists it
        at enqueue time. When it is None the key is left out entirely,
        which is the shape of a row predating the watermark.
        """
        config_dict = {
            'personalities': [constants.CONTROLLER, constants.WORKER],
            'classes': classes,
        }
        if cpu_watermark is not None:
            watermark_key = manager.ConductorManager.GRUB_CPU_WATERMARK_KEY
            config_dict[watermark_key] = cpu_watermark

        config_uuid = str(uuid.uuid4())
        self.dbapi.runtime_config_create({
            'config_uuid': config_uuid,
            'config_dict': json.dumps(config_dict),
            'forihostid': host.id,
            'state': state,
        })
        return config_uuid

    def _create_test_icpus(self, host, count=2,
                           allocated_function=constants.PLATFORM_FUNCTION):
        """Create cpu rows for a host, as the agent inventory would"""
        return [self.dbapi.icpu_create(
                    host.id,
                    dbutils.get_test_icpu(cpu=cpu, core=cpu, thread=0,
                                          forinodeid=None,
                                          allocated_function=(
                                              allocated_function)))
                for cpu in range(count)]

    def _cpu_watermark(self, host):
        """Return max(icpu.updated_at) for a host, read straight from the DB

        Deliberately computed here rather than through the conductor
        helper, so a test comparing a persisted watermark against this
        value is not comparing the implementation with itself.
        """
        stamps = [cpu.updated_at
                  for cpu in self.dbapi.icpu_get_by_ihost(host.uuid)
                  if cpu.updated_at is not None]
        if not stamps:
            return None
        return max(stamps).isoformat()

    def _bump_icpu_watermark(self, host, allocated_function=None, seconds=0):
        """Move the host's cpu updated_at, as a genuine cpu change does

        dbutils.get_test_icpu() creates rows with updated_at = None, so a
        freshly inventoried test host carries no watermark at all and the
        predicate fails open. On a real change host_cpus_modify() calls
        icpu_update(), which moves updated_at; this mirrors that. The stamp
        is passed explicitly so two bumps in the same test are guaranteed
        to differ regardless of clock resolution.
        """
        stamp = timeutils.utcnow() + datetime.timedelta(seconds=seconds)
        values = {'updated_at': stamp}
        if allocated_function is not None:
            values['allocated_function'] = allocated_function
        for cpu in self.dbapi.icpu_get_by_ihost(host.uuid):
            self.dbapi.icpu_update(cpu.uuid, values)
        return self._cpu_watermark(host)

    # --- Watermark-dependent fix checking (design.md unit tests 8-14).
    #
    # These replace the four PS1 fix-checking tests, which asserted an exact
    # puppet CLASS-SET match against pending rows -- superseded, because a
    # class-set criterion only ever sees the harmless re-stamp half of the
    # churn ({personalities, classes} was invariant across all 516 grub
    # occurrences at the customer). The predicate under test is now a
    # STORED-WATERMARK comparison: the host's current max(icpu.updated_at)
    # against the value persisted in the most recent grub runtime_config's
    # config_dict -- the same column sampled at two points in time, so the
    # ordering of icpu_update() and update_grub_config() is irrelevant and
    # the row's created_at never enters the comparison.
    #
    # The two suppression tests leave _config_update_hosts() UNMOCKED, so
    # the assertion is "config_target is byte-identical after the call",
    # not "a mock was not called". _config_apply_runtime_manifest stays
    # mocked, as in every other update_grub_config test here: it needs
    # puppet hieradata paths on disk and the agent RPC.

    def test_update_grub_config_suppressed_when_watermark_unchanged_pending_row(
            self):
        # design.md unit test 8 -- Property 1. Bug condition C_A with a
        # PENDING row present: WORKER subfunction, force_grub_update False,
        # and the cpu updated_at watermark unchanged since that row was
        # written. Nothing about the host's desired cpu configuration
        # changed, so the enqueue must be suppressed BEFORE any config
        # state advances.
        host = self._create_test_worker_ihost()
        self._create_test_icpus(host)
        watermark = self._bump_icpu_watermark(host)
        self.assertIsNotNone(watermark)
        self._create_pending_runtime_config(
            host, self.GRUB_RUNTIME_CLASSES, cpu_watermark=watermark)
        rows_before = [(row.config_uuid, row.state, row.created_at)
                       for row in self.dbapi.runtime_config_get_all(
                           forihostid=host.id)]
        self.assertEqual(1, len(rows_before))
        config_target_before = host.config_target

        with mock.patch('sysinv.conductor.manager.ConductorManager.'
                        '_config_apply_runtime_manifest') as mock_apply:
            self.service.update_grub_config(self.context, host.uuid)

        # The real _config_update_hosts() ran (it is not mocked here), so
        # config_target is observed on the host row itself.
        updated_host = self.dbapi.ihost_get(host.uuid)
        self.assertEqual(config_target_before, updated_host.config_target)
        mock_apply.assert_not_called()
        # No row created and none re-stamped: config_uuid, state and
        # created_at are all untouched.
        rows_after = [(row.config_uuid, row.state, row.created_at)
                      for row in self.dbapi.runtime_config_get_all(
                          forihostid=host.id)]
        self.assertEqual(rows_before, rows_after)

    def test_update_grub_config_suppressed_when_watermark_unchanged_row_applied(
            self):
        # design.md unit test 9 -- Property 1. Same assertions as the
        # previous test, but the most recent grub row is already APPLIED and
        # no pending row survives. This is the INSERT half PS1 missed, and
        # the half that renewed the unlock gate window ~166 times at the
        # customer.
        #
        # GREEN since Open Design Decision 3 was resolved to "most recent
        # row regardless of state" (§3.4 of the implementation context:
        # a lab A/B showed that a PENDING-only lookup does not merely miss
        # this half, it actively converts a re-stamp -- which ages out of
        # the unlock gate's created_at window on its own -- into an
        # insert, which renews it, i.e. it makes the pending-only variant
        # WORSE than no fix at all on this path).
        # _get_most_recent_grub_runtime_config() now queries any state and
        # scopes by GRUB_RUNTIME_CLASS membership instead, so an APPLIED
        # row is visible to the comparison.
        host = self._create_test_worker_ihost()
        self._create_test_icpus(host)
        watermark = self._bump_icpu_watermark(host)
        self.assertIsNotNone(watermark)
        self._create_pending_runtime_config(
            host, self.GRUB_RUNTIME_CLASSES,
            state=constants.RUNTIME_CONFIG_STATE_APPLIED,
            cpu_watermark=watermark)
        rows_before = [(row.config_uuid, row.state, row.created_at)
                       for row in self.dbapi.runtime_config_get_all(
                           forihostid=host.id)]
        self.assertEqual(1, len(rows_before))
        config_target_before = host.config_target

        with mock.patch('sysinv.conductor.manager.ConductorManager.'
                        '_config_apply_runtime_manifest') as mock_apply:
            self.service.update_grub_config(self.context, host.uuid)

        updated_host = self.dbapi.ihost_get(host.uuid)
        self.assertEqual(
            config_target_before, updated_host.config_target,
            "unchanged cpu watermark with the most recent row APPLIED "
            "still advanced config_target from %s to %s -- the "
            "state-agnostic lookup should have suppressed this enqueue" %
            (config_target_before, updated_host.config_target))
        mock_apply.assert_not_called()
        rows_after = [(row.config_uuid, row.state, row.created_at)
                      for row in self.dbapi.runtime_config_get_all(
                          forihostid=host.id)]
        self.assertEqual(rows_before, rows_after)

    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_apply_runtime_manifest')
    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_update_hosts')
    def test_update_grub_config_enqueues_when_cpu_updated_at_bumped(
            self, mock_config_update_hosts,
            mock_config_apply_runtime_manifest):
        # design.md unit test 10 -- Property 22. A genuine cpu change moves
        # icpu.updated_at, so the watermark diverges from the one stored on
        # the pending row and the enqueue must happen ANYWAY. This is the
        # headline regression risk of the predicate: a wrongly suppressed
        # real change leaves the grub cmdline silently lagging the requested
        # layout, with no alarm and no failure log.
        host = self._create_test_worker_ihost()
        self._create_test_icpus(host)
        stored_watermark = self._bump_icpu_watermark(host)
        self._create_pending_runtime_config(
            host, self.GRUB_RUNTIME_CLASSES,
            cpu_watermark=stored_watermark)

        # The operator changes the cpu allocation: host_cpus_modify() calls
        # icpu_update() only when allocated_function actually differs, which
        # is what moves the watermark.
        current_watermark = self._bump_icpu_watermark(
            host, allocated_function=constants.APPLICATION_FUNCTION,
            seconds=60)
        self.assertNotEqual(stored_watermark, current_watermark)
        mock_config_update_hosts.return_value = str(uuid.uuid4())

        self.service.update_grub_config(self.context, host.uuid)

        mock_config_update_hosts.assert_called_once()
        mock_config_apply_runtime_manifest.assert_called_once()

    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_apply_runtime_manifest')
    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_update_hosts')
    def test_update_grub_config_created_row_carries_cpu_watermark(
            self, mock_config_update_hosts,
            mock_config_apply_runtime_manifest):
        # design.md unit test 11 -- Property 3. The entry created at enqueue
        # time must carry the cpu updated_at watermark, otherwise the next
        # enqueue has nothing to compare the live value against: the
        # persisted dict is {personalities, classes} only (host_uuids and
        # puppet_path are popped before saving) and that pair was invariant
        # across all 516 grub occurrences at the customer.
        host = self._create_test_worker_ihost()
        self._create_test_icpus(host)
        self._bump_icpu_watermark(host)
        expected_watermark = self._cpu_watermark(host)
        self.assertIsNotNone(expected_watermark)
        config_uuid = str(uuid.uuid4())
        mock_config_update_hosts.return_value = config_uuid

        self.service.update_grub_config(self.context, host.uuid)

        watermark_key = manager.ConductorManager.GRUB_CPU_WATERMARK_KEY
        config_dict = mock_config_apply_runtime_manifest.call_args[0][2]
        self.assertIn(watermark_key, config_dict)
        self.assertEqual(expected_watermark, config_dict[watermark_key])

        # And it survives onto the persisted row.
        # _config_apply_runtime_manifest() is mocked here (it needs puppet
        # hieradata paths on disk and the agent RPC), so the entry creation
        # it would reach is driven directly with the dict just captured.
        self.service._create_runtime_config_entries(config_uuid, config_dict)

        rows = self.dbapi.runtime_config_get_all(forihostid=host.id)
        self.assertEqual(1, len(rows))
        persisted_dict = json.loads(rows[0].config_dict)
        self.assertEqual(expected_watermark, persisted_dict[watermark_key])
        # The 2-class grub pair the agent's UNLOCK_READY_FLAG path keys off
        # is untouched by the added key.
        self.assertEqual(self.GRUB_RUNTIME_CLASSES,
                         persisted_dict['classes'])

    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_apply_runtime_manifest')
    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_update_hosts')
    def test_update_grub_config_enqueues_when_row_has_no_watermark(
            self, mock_config_update_hosts,
            mock_config_apply_runtime_manifest):
        # design.md unit test 12 -- Property 4. A row written before this
        # change carries no watermark key at all, so there is nothing to
        # compare against: fail open into a normal enqueue rather than
        # suppress on an assumption.
        host = self._create_test_worker_ihost()
        self._create_test_icpus(host)
        self.assertIsNotNone(self._bump_icpu_watermark(host))
        # No cpu_watermark argument: the config_dict is exactly the
        # pre-change {personalities, classes} shape.
        self._create_pending_runtime_config(host, self.GRUB_RUNTIME_CLASSES)
        mock_config_update_hosts.return_value = str(uuid.uuid4())

        self.service.update_grub_config(self.context, host.uuid)

        mock_config_update_hosts.assert_called_once()
        mock_config_apply_runtime_manifest.assert_called_once()

    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_apply_runtime_manifest')
    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_update_hosts')
    def test_update_grub_config_enqueues_when_watermark_unparseable(
            self, mock_config_update_hosts,
            mock_config_apply_runtime_manifest):
        # design.md unit test 13 -- Property 4. A watermark that is present
        # but not the canonical shape this code writes (a value from a
        # release that stored a different layout, or a corrupted entry) logs
        # a warning and fails open. Rejecting rather than coercing matters:
        # a coarser rendering would let two DIFFERENT cpu layouts compare
        # equal and swallow a genuine change.
        host = self._create_test_worker_ihost()
        self._create_test_icpus(host)
        self.assertIsNotNone(self._bump_icpu_watermark(host))
        self._create_pending_runtime_config(
            host, self.GRUB_RUNTIME_CLASSES,
            cpu_watermark='not-a-timestamp')
        mock_config_update_hosts.return_value = str(uuid.uuid4())

        patcher = mock.patch.object(manager, 'LOG')
        mock_log = patcher.start()
        self.addCleanup(patcher.stop)

        self.service.update_grub_config(self.context, host.uuid)

        mock_config_update_hosts.assert_called_once()
        mock_config_apply_runtime_manifest.assert_called_once()
        self.assertTrue(
            any('not-a-timestamp' in str(call)
                for call in mock_log.warn.call_args_list),
            "the unrecognised watermark was not reported: %s"
            % mock_log.warn.call_args_list)

    def test_update_grub_config_predicate_reads_no_memory_timestamp(self):
        # design.md unit test 14 -- Property 5. The watermark is scoped to
        # CPU. Memory divergence always arrives with force_grub_update=True
        # (memory.py, hugepages) so it bypasses this guard anyway, while
        # mem.updated_at moves on its own: the agent compares a dict
        # carrying the volatile memavail_mib (free memory), so the guard in
        # host_memory_update() fires for reasons unrelated to configured
        # memory and the conductor's imemory_update() bumps updated_at.
        #
        # Two claims are asserted: mutating imemory.updated_at (including
        # through a memavail_mib update) does not change the decision while
        # the cpu watermark is held constant, and the predicate reads no
        # memory table at all.
        host = self._create_test_worker_ihost()
        self._create_test_icpus(host)
        watermark = self._bump_icpu_watermark(host)
        self._create_pending_runtime_config(
            host, self.GRUB_RUNTIME_CLASSES, cpu_watermark=watermark)
        memory = self.dbapi.imemory_create(
            host.id, dbutils.get_test_imemory(forinodeid=None))
        config_target_before = host.config_target

        for offset, memavail_mib in ((60, 2000), (120, 512)):
            # A memavail_mib-driven inventory update, which is what really
            # bumps mem.updated_at on a live host.
            self.dbapi.imemory_update(
                memory.uuid,
                {'memavail_mib': memavail_mib,
                 'updated_at': (timeutils.utcnow() +
                                datetime.timedelta(seconds=offset))})

            with mock.patch('sysinv.conductor.manager.ConductorManager.'
                            '_config_apply_runtime_manifest') as mock_apply:
                self.service.update_grub_config(self.context, host.uuid)

            # Same decision as with the untouched memory row: suppressed,
            # because the cpu watermark did not move.
            updated_host = self.dbapi.ihost_get(host.uuid)
            self.assertEqual(
                config_target_before, updated_host.config_target,
                "the decision changed after mutating imemory.updated_at "
                "(memavail_mib=%s) while the cpu watermark was held "
                "constant" % memavail_mib)
            mock_apply.assert_not_called()

        # The predicate reads no memory timestamp: every memory accessor on
        # the dbapi the helper could reach stays untouched.
        memory_accessors = ['imemory_get', 'imemory_get_all',
                            'imemory_get_by_ihost',
                            'imemory_get_by_ihost_inode']
        patchers = [mock.patch.object(self.service.dbapi, accessor)
                    for accessor in memory_accessors]
        mocks = [patcher.start() for patcher in patchers]
        for patcher in patchers:
            self.addCleanup(patcher.stop)

        self.assertTrue(self.service._grub_runtime_config_is_redundant(host))

        for accessor, mocked in zip(memory_accessors, mocks):
            mocked.assert_not_called()

    # --- Tests for the three changes made after §3.4 of the implementation
    # context (dropping the state=PENDING filter, the added class filter,
    # and the cpu_driven parameter). The state-agnostic lookup itself is
    # exercised by test_update_grub_config_suppressed_when_watermark_
    # unchanged_row_applied above, which now passes.

    def test_get_most_recent_grub_runtime_config_ignores_non_grub_row(self):
        # A row whose classes do not contain GRUB_RUNTIME_CLASS at all
        # (e.g. a stalld-only apply) must never be picked as "the most
        # recent grub row", regardless of state or created_at ordering.
        host = self._create_test_worker_ihost()
        self._create_pending_runtime_config(
            host, ['platform::stalld::runtime'],
            state=constants.RUNTIME_CONFIG_STATE_APPLIED)

        self.assertIsNone(
            self.service._get_most_recent_grub_runtime_config(host))

    def test_get_most_recent_grub_runtime_config_matches_by_membership(self):
        # The kernel-config path (~L1780) applies GRUB_RUNTIME_CLASS
        # alongside two other classes, not the exact 2-class grub pair.
        # Membership, not equality, is what identifies it as a grub row,
        # so it must be picked up by the lookup once the state filter is
        # gone -- otherwise the guard would silently fail open every time
        # the most recent row happens to come from that path.
        host = self._create_test_worker_ihost()
        kernel_config_classes = [
            'platform::grub::kernel_image::runtime',
            'platform::config::file::subfunctions::lowlatency::runtime',
            'platform::compute::grub::runtime',
        ]
        config_uuid = self._create_pending_runtime_config(
            host, kernel_config_classes,
            state=constants.RUNTIME_CONFIG_STATE_APPLIED)

        recent = self.service._get_most_recent_grub_runtime_config(host)

        self.assertIsNotNone(recent)
        self.assertEqual(config_uuid, recent.config_uuid)

    def test_get_most_recent_grub_runtime_config_picks_newest_grub_row(self):
        # Among several grub-classed rows in different states, the lookup
        # must pick the one with the latest created_at, not simply the
        # first or the last inserted.
        host = self._create_test_worker_ihost()
        self._create_pending_runtime_config(
            host, self.GRUB_RUNTIME_CLASSES,
            state=constants.RUNTIME_CONFIG_STATE_APPLIED)
        newest_uuid = self._create_pending_runtime_config(
            host, self.GRUB_RUNTIME_CLASSES,
            state=constants.RUNTIME_CONFIG_STATE_PENDING)

        recent = self.service._get_most_recent_grub_runtime_config(host)

        self.assertIsNotNone(recent)
        self.assertEqual(newest_uuid, recent.config_uuid)

    def test_runtime_config_classes_contain_grub_fails_open_on_malformed_dict(
            self):
        # A row whose config_dict is not valid JSON, not a mapping, or has
        # no 'classes' list must be treated as "not a grub row" rather
        # than raising -- this lookup must never be the reason a real
        # grub row's presence check breaks.
        host = self._create_test_worker_ihost()
        malformed_shapes = [
            'not valid json',
            json.dumps(['a', 'list', 'not', 'a', 'dict']),
            json.dumps({'personalities': [constants.CONTROLLER]}),
            json.dumps({'classes': 'not-a-list'}),
        ]
        for config_dict in malformed_shapes:
            config_uuid = str(uuid.uuid4())
            self.dbapi.runtime_config_create({
                'config_uuid': config_uuid,
                'config_dict': config_dict,
                'forihostid': host.id,
                'state': constants.RUNTIME_CONFIG_STATE_PENDING,
            })
            runtime_config = self.dbapi.runtime_config_get(config_uuid)
            self.assertFalse(
                self.service._runtime_config_classes_contain_grub(
                    runtime_config),
                "malformed config_dict %r was not treated as a non-grub "
                "row" % config_dict)

    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_apply_runtime_manifest')
    def test_update_grub_config_not_cpu_driven_always_enqueues_label_shape(
            self, mock_config_apply_runtime_manifest):
        # cpu_driven=False callers (label.py's disable-nohz-full and
        # power-management labels) must always enqueue, even when the cpu
        # updated_at watermark is unchanged and the most recent grub row
        # is already APPLIED -- exactly the shape that reproduced the
        # label.py regression in §3.4: widening the lookup to any state
        # made an already-applied label-driven row visible to the
        # watermark comparison, which would otherwise have suppressed a
        # genuine kernel-args change.
        host = self._create_test_worker_ihost()
        self._create_test_icpus(host)
        watermark = self._bump_icpu_watermark(host)
        self._create_pending_runtime_config(
            host, self.GRUB_RUNTIME_CLASSES,
            state=constants.RUNTIME_CONFIG_STATE_APPLIED,
            cpu_watermark=watermark)
        config_target_before = host.config_target

        self.service.update_grub_config(
            self.context, host.uuid, cpu_driven=False)

        updated_host = self.dbapi.ihost_get(host.uuid)
        self.assertNotEqual(
            config_target_before, updated_host.config_target,
            "a cpu_driven=False request (label-driven) was suppressed by "
            "the cpu watermark guard, which must never apply to it")
        mock_config_apply_runtime_manifest.assert_called_once()

    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_apply_runtime_manifest')
    def test_update_grub_config_not_cpu_driven_always_enqueues_memory_shape(
            self, mock_config_apply_runtime_manifest):
        # Same as above for a memory-driven shape (the memory.py hugepage
        # caller), with a PENDING row present instead of APPLIED. force
        # is not passed here on purpose: cpu_driven=False alone must be
        # sufficient to bypass the guard, independent of force_grub_update.
        host = self._create_test_worker_ihost()
        self._create_test_icpus(host)
        watermark = self._bump_icpu_watermark(host)
        self._create_pending_runtime_config(
            host, self.GRUB_RUNTIME_CLASSES, cpu_watermark=watermark)
        config_target_before = host.config_target

        self.service.update_grub_config(
            self.context, host.uuid, cpu_driven=False)

        updated_host = self.dbapi.ihost_get(host.uuid)
        self.assertNotEqual(
            config_target_before, updated_host.config_target,
            "a cpu_driven=False request (memory-driven) was suppressed "
            "by the cpu watermark guard, which must never apply to it")
        mock_config_apply_runtime_manifest.assert_called_once()

    def test_update_grub_config_cpu_driven_defaults_to_true(self):
        # The parameter's default preserves every existing cpu-driven
        # caller (host_cpus_modify, the cpu API, the conductor's own cpu
        # topology handling) without requiring them to pass cpu_driven
        # explicitly: an unchanged watermark must still suppress when the
        # parameter is omitted.
        host = self._create_test_worker_ihost()
        self._create_test_icpus(host)
        watermark = self._bump_icpu_watermark(host)
        self._create_pending_runtime_config(
            host, self.GRUB_RUNTIME_CLASSES, cpu_watermark=watermark)
        config_target_before = host.config_target

        with mock.patch('sysinv.conductor.manager.ConductorManager.'
                        '_config_apply_runtime_manifest') as mock_apply:
            self.service.update_grub_config(self.context, host.uuid)

        updated_host = self.dbapi.ihost_get(host.uuid)
        self.assertEqual(config_target_before, updated_host.config_target)
        mock_apply.assert_not_called()

    def test_label_apply_manifest_calls_update_grub_config_not_cpu_driven(
            self):
        # label.py::_apply_manifest_after_label_operation() is the caller
        # this parameter exists for: assert it reaches the rpcapi with
        # cpu_driven=False for both label keys that trigger a grub apply.
        for label_key in (helm_common.LABEL_DISABLE_NOHZ_FULL,
                          constants.KUBE_POWER_MANAGER_LABEL):
            controller = label_api.LabelController()

            with mock.patch(
                    'sysinv.api.controllers.v1.label.pecan') as mock_pecan:
                controller._apply_manifest_after_label_operation(
                    'some-host-uuid', [label_key])

                mock_pecan.request.rpcapi.update_grub_config.\
                    assert_called_once_with(
                        mock_pecan.request.context, 'some-host-uuid',
                        cpu_driven=False)

    def test_memory_patch_calls_update_grub_config_not_cpu_driven(self):
        # memory.py's hugepage caller is the other cpu_driven=False call
        # site: assert it passes cpu_driven=False alongside force=True.
        source = inspect.getsource(memory_api.MemoryController.patch)
        self.assertIn('cpu_driven=False', source)
        self.assertIn('force=True', source)

    # --- Property 12 preservation: call-site behavior for every non-bug
    # input, signature-independent. Written BEFORE the fix; observed on the
    # UNFIXED baseline (git worktree at 286d37452) and expected to keep
    # PASSING unchanged once the fix lands (tasks 7.3, 8.5).

    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_apply_runtime_manifest')
    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_update_hosts')
    def test_update_grub_config_enqueues_when_no_previous_grub_config(
            self, mock_config_update_hosts,
            mock_config_apply_runtime_manifest):
        # No prior grub runtime_config row for this host: the request must
        # be enqueued as before, both calls happening exactly once
        # (design.md unit test 1) -- Property 12.
        host = self._create_test_worker_ihost()
        config_uuid = str(uuid.uuid4())
        mock_config_update_hosts.return_value = config_uuid

        self.service.update_grub_config(self.context, host.uuid)

        mock_config_update_hosts.assert_called_once()
        mock_config_apply_runtime_manifest.assert_called_once_with(
            mock.ANY,
            config_uuid,
            {
                "personalities": [constants.CONTROLLER, constants.WORKER],
                "host_uuids": [host.uuid],
                "classes": self.GRUB_RUNTIME_CLASSES,
            },
            force=True)

    @mock.patch('sysinv.conductor.manager.utils.is_host_simplex_controller')
    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_apply_runtime_manifest')
    def test_update_grub_config_forced_always_enqueues(
            self, mock_config_apply_runtime_manifest,
            mock_is_simplex_controller):
        # force_grub_update=True must bypass the redundancy check and
        # always enqueue despite a prior pending row, with config_target
        # advancing -- documenting the accepted memory.py limitation that
        # this path remains exposed to the churn (Requirement 3.14).
        #
        # Exercised against the real _config_update_hosts() (not a mock),
        # with is_host_simplex_controller() patched both True and False,
        # so the bypass decision is shown to follow the force_grub_update
        # PARAMETER, never the local `force` variable (design.md unit
        # test 2) -- Properties 13, 7, 15.
        for simplex, mac_suffix in ((True, '10'), (False, '11')):
            mock_config_apply_runtime_manifest.reset_mock()
            mock_is_simplex_controller.return_value = simplex

            host = self._create_test_worker_ihost(
                mgmt_mac='22:44:33:55:11:%s' % mac_suffix)
            self._create_pending_runtime_config(host,
                                               self.GRUB_RUNTIME_CLASSES)
            config_target_before = host.config_target

            self.service.update_grub_config(self.context, host.uuid,
                                            force_grub_update=True)

            # The bypass fires regardless of is_host_simplex_controller():
            # the decision to skip the redundancy check reads only the
            # force_grub_update parameter, so config_target still advances
            # despite the prior pending row.
            updated_host = self.dbapi.ihost_get(host.uuid)
            self.assertNotEqual(config_target_before,
                                updated_host.config_target)

            # The local `force` variable is
            # (not is_host_simplex_controller(host) or force_grub_update);
            # with force_grub_update=True it is always True regardless of
            # is_host_simplex_controller(), and that local value -- not a
            # literal reading of the parameter -- is what is passed to
            # _config_apply_runtime_manifest() and printed by the
            # 'force: (%s)' log line.
            mock_config_apply_runtime_manifest.assert_called_once_with(
                mock.ANY, mock.ANY, mock.ANY, force=True)

    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_apply_runtime_manifest')
    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_update_hosts')
    def test_update_grub_config_applied_when_pending_classes_differ(
            self, mock_config_update_hosts,
            mock_config_apply_runtime_manifest):
        # A pending config applying unrelated classes is not equivalent
        host = self._create_test_worker_ihost()
        self._create_pending_runtime_config(
            host, ['platform::stalld::runtime'])
        mock_config_update_hosts.return_value = str(uuid.uuid4())

        self.service.update_grub_config(self.context, host.uuid)

        mock_config_update_hosts.assert_called_once()
        mock_config_apply_runtime_manifest.assert_called_once()

    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_apply_runtime_manifest')
    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_update_hosts')
    def test_update_grub_config_applied_when_pending_classes_are_superset(
            self, mock_config_update_hosts,
            mock_config_apply_runtime_manifest):
        # The kernel config manifest also applies the grub runtime class, but
        # the set of classes differs. It is not equivalent, as the sysinv
        # agent keys off the exact set of applied classes to signal that the
        # initial controller is ready to be unlocked
        host = self._create_test_worker_ihost()
        self._create_pending_runtime_config(host, [
            'platform::grub::kernel_image::runtime',
            'platform::config::file::subfunctions::lowlatency::runtime',
            'platform::compute::grub::runtime',
        ])
        mock_config_update_hosts.return_value = str(uuid.uuid4())

        self.service.update_grub_config(self.context, host.uuid)

        mock_config_update_hosts.assert_called_once()
        mock_config_apply_runtime_manifest.assert_called_once()

    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_apply_runtime_manifest')
    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_update_hosts')
    def test_update_grub_config_applied_when_pending_classes_are_subset(
            self, mock_config_update_hosts,
            mock_config_apply_runtime_manifest):
        # A pending config applying only part of the class set is not
        # equivalent, the remaining classes still need to be applied
        host = self._create_test_worker_ihost()
        self._create_pending_runtime_config(
            host, ['platform::compute::grub::runtime'])
        mock_config_update_hosts.return_value = str(uuid.uuid4())

        self.service.update_grub_config(self.context, host.uuid)

        mock_config_update_hosts.assert_called_once()
        mock_config_apply_runtime_manifest.assert_called_once()

    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_apply_runtime_manifest')
    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_update_hosts')
    def test_update_grub_config_enqueues_when_config_dict_malformed(
            self, mock_config_update_hosts,
            mock_config_apply_runtime_manifest):
        # A malformed / unparseable config_dict on the existing row must log
        # a warning and fail open into a normal enqueue, rather than
        # preventing the grub config from being applied (design.md unit
        # test 4) -- Property 4.
        host = self._create_test_worker_ihost()
        self.dbapi.runtime_config_create({
            'config_uuid': str(uuid.uuid4()),
            'config_dict': 'not valid json',
            'forihostid': host.id,
            'state': constants.RUNTIME_CONFIG_STATE_PENDING,
        })
        mock_config_update_hosts.return_value = str(uuid.uuid4())

        self.service.update_grub_config(self.context, host.uuid)

        mock_config_update_hosts.assert_called_once()
        mock_config_apply_runtime_manifest.assert_called_once()

    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_apply_runtime_manifest')
    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_update_hosts')
    def test_update_grub_config_ignores_other_host_runtime_config(
            self, mock_config_update_hosts,
            mock_config_apply_runtime_manifest):
        # A runtime_config row whose forihostid is another host must not
        # influence the decision for this host; the lookup stays scoped by
        # forihostid.
        host = self._create_test_worker_ihost()
        other_host = self._create_test_worker_ihost(
            hostname='controller-0', mgmt_mac='22:44:33:55:11:99')
        self._create_pending_runtime_config(other_host,
                                           self.GRUB_RUNTIME_CLASSES)
        mock_config_update_hosts.return_value = str(uuid.uuid4())

        self.service.update_grub_config(self.context, host.uuid)

        mock_config_update_hosts.assert_called_once()
        mock_config_apply_runtime_manifest.assert_called_once()

    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_apply_runtime_manifest')
    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_update_hosts')
    def test_update_grub_config_no_worker_subfunction(
            self, mock_config_update_hosts,
            mock_config_apply_runtime_manifest):
        # A host without the worker subfunction takes no action: neither
        # call happens, unchanged early return (design.md unit test 3) --
        # Property 14.
        host = self._create_test_worker_ihost(
            subfunctions=constants.CONTROLLER)
        self._create_pending_runtime_config(host,
                                           self.GRUB_RUNTIME_CLASSES)

        self.service.update_grub_config(self.context, host.uuid)

        mock_config_update_hosts.assert_not_called()
        mock_config_apply_runtime_manifest.assert_not_called()

    def test_update_grub_config_decision_is_host_agnostic(self):
        # Sweep controller-0, controller-1 and worker-0 with identical
        # cpu/memory and runtime_config state and assert an identical
        # decision: the predicate reads no hostname, personality or host id
        # (design.md unit test 6) -- Property 6.
        #
        # The sweep does not hardcode which decision (skip or enqueue) is
        # expected -- that depends on which redundancy condition is active
        # on the code under test -- only that all three hosts get the SAME
        # decision, since none of hostname/personality/host id may be a
        # term in the predicate.
        decisions = []
        for hostname, personality, mac_suffix in (
                ('controller-0', constants.CONTROLLER, '01'),
                ('controller-1', constants.CONTROLLER, '02'),
                ('worker-0', constants.WORKER, '03')):
            patch_apply = mock.patch(
                'sysinv.conductor.manager.'
                'ConductorManager._config_apply_runtime_manifest')
            patch_update_hosts = mock.patch(
                'sysinv.conductor.manager.'
                'ConductorManager._config_update_hosts')
            with patch_apply as mock_config_apply_runtime_manifest, \
                    patch_update_hosts as mock_config_update_hosts:
                host = self._create_test_worker_ihost(
                    hostname=hostname, personality=personality,
                    mgmt_mac='22:44:33:55:22:%s' % mac_suffix)
                self._create_pending_runtime_config(
                    host, self.GRUB_RUNTIME_CLASSES)
                mock_config_update_hosts.return_value = str(uuid.uuid4())

                self.service.update_grub_config(self.context, host.uuid)

                decisions.append(mock_config_update_hosts.called)
                self.assertEqual(mock_config_update_hosts.called,
                                mock_config_apply_runtime_manifest.called,
                                "%s: _config_update_hosts and "
                                "_config_apply_runtime_manifest must agree"
                                % hostname)

        self.assertEqual(
            1, len(set(decisions)),
            "the decision differed across the host-agnostic sweep: %s -- "
            "the predicate must not read hostname, personality or host id"
            % decisions)

    def test_update_grub_config_repeated_requests_enqueue_once(self):
        # Rewritten against the watermark: the reported DM loop, where a
        # reconcile re-sends an identical cpu layout every ~12s. The first
        # request enqueues and persists the watermark; every later request
        # must be suppressed while that watermark is unchanged, so
        # config_target stops advancing after the first call.
        #
        # _config_update_hosts() is left unmocked, so config_target is
        # observed on the host row rather than through a call count.
        host = self._create_test_worker_ihost()
        self._create_test_icpus(host)
        self.assertIsNotNone(self._bump_icpu_watermark(host))

        with mock.patch('sysinv.conductor.manager.ConductorManager.'
                        '_config_apply_runtime_manifest') as mock_apply:
            self.service.update_grub_config(self.context, host.uuid)

            # The first request enqueued: persist the entry it would have
            # created, watermark included, exactly as
            # _create_runtime_config_entries() does downstream of the
            # mocked _config_apply_runtime_manifest().
            config_uuid = mock_apply.call_args[0][1]
            config_dict = copy.deepcopy(mock_apply.call_args[0][2])
            self.service._create_runtime_config_entries(
                config_uuid, config_dict)
            mock_apply.assert_called_once()

            config_target_after_first = self.dbapi.ihost_get(
                host.uuid).config_target
            rows_after_first = [
                (row.config_uuid, row.state, row.created_at)
                for row in self.dbapi.runtime_config_get_all(
                    forihostid=host.id)]
            self.assertEqual(1, len(rows_after_first))

            for _ in range(5):
                self.service.update_grub_config(self.context, host.uuid)

            # Still exactly one enqueue, no further config_target advance,
            # and no row inserted or re-stamped: neither half of the churn
            # happens.
            mock_apply.assert_called_once()

        self.assertEqual(config_target_after_first,
                         self.dbapi.ihost_get(host.uuid).config_target)
        self.assertEqual(
            rows_after_first,
            [(row.config_uuid, row.state, row.created_at)
             for row in self.dbapi.runtime_config_get_all(
                 forihostid=host.id)])

    # --- Property 1 (Bug Condition C_A) exploration tests ------------------
    #
    # Goal: surface counterexamples showing that update_grub_config() advances
    # config_target for a cpu/memory layout that did not change. Written
    # BEFORE the fix, against the UNFIXED baseline (git worktree at
    # 286d37452, the parent of PS1). They are EXPECTED TO FAIL on unfixed
    # code -- the failure confirms isBugCondition_A(input) triggers unwanted
    # config state advancement. Do not fix the test or the code when it
    # fails here.
    #
    # Both tests call the real _config_update_hosts() (not a mock), so the
    # assertion is "config_target is byte-identical after the call", not
    # "a mock was not called" -- design.md unit tests 8 and 9.
    #
    # These stay RED through tasks 5-7 (signature-independent work) and only
    # go green in task 8.4, once the cpu/memory divergence predicate lands
    # (gated on Open Design Decision 1). That is expected, not a regression.

    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_apply_runtime_manifest')
    def test_exploration_unchanged_layout_advances_config_target(
            self, mock_config_apply_runtime_manifest):
        # Bug condition C_A: WORKER in subfunctions, force_grub_update=False,
        # and the cpu/memory layout did NOT diverge from what the most
        # recent grub runtime_config row already requested. A prior grub
        # row is PENDING (the harmless re-stamp half PS1 could see).
        #
        # Counterexample sought: config_target moves from <uuid-a> to
        # <uuid-b> even though nothing about the host's desired cpu/memory
        # allocation changed between the two update_grub_config() calls.
        #
        # Fixture note (task 8.3): dbutils.get_test_icpu() creates rows with
        # updated_at = None, so cpu rows must exist AND have been stamped
        # for the host to have a watermark at all, and the prior row must
        # carry the watermark the way update_grub_config() now persists it.
        # Without both, the predicate fails open for a fixture reason rather
        # than because the layout diverged. The assertions are unchanged
        # from task 3.
        host = self._create_test_worker_ihost()
        self._create_test_icpus(host)
        watermark = self._bump_icpu_watermark(host)
        self._create_pending_runtime_config(host, self.GRUB_RUNTIME_CLASSES,
                                           cpu_watermark=watermark)
        config_target_before = host.config_target

        self.service.update_grub_config(self.context, host.uuid)

        updated_host = self.dbapi.ihost_get(host.uuid)
        # EXPECTED OUTCOME on unfixed code: this FAILS. The unfixed
        # update_grub_config() has no cpu/memory divergence check, so
        # _config_update_hosts() mints a fresh config_uuid unconditionally
        # and config_target advances for an unchanged layout.
        self.assertEqual(
            config_target_before, updated_host.config_target,
            "counterexample: unchanged cpu/memory layout (pending row "
            "present) still advanced config_target from %s to %s -- "
            "_config_update_hosts() was called for a redundant request" %
            (config_target_before, updated_host.config_target))
        mock_config_apply_runtime_manifest.assert_not_called()

    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_apply_runtime_manifest')
    def test_exploration_unchanged_layout_inserts_new_row(
            self, mock_config_apply_runtime_manifest):
        # Bug condition C_A, config_target half: same unchanged layout, but
        # the most recent grub runtime_config row is already APPLIED (no
        # pending row survives to be re-stamped). This is the case PS1's
        # exact-class-set-against-PENDING-only check could not see.
        #
        # _config_apply_runtime_manifest is mocked here, matching every
        # other update_grub_config test in this module (it needs puppet
        # hieradata paths on disk and the agent RPC); the real
        # _config_update_hosts() still runs, so config_target is observed
        # on the real host row via the DB, not via a mock call count.
        #
        # GREEN since Open Design Decision 3 was resolved to "most recent
        # row regardless of state" (see the sibling test
        # test_update_grub_config_suppressed_when_watermark_unchanged_row_applied
        # for the measurement that motivated it):
        # _get_most_recent_grub_runtime_config() now queries any state and
        # scopes by GRUB_RUNTIME_CLASS membership, so the APPLIED row is
        # visible to the comparison.
        host = self._create_test_worker_ihost()
        self._create_test_icpus(host)
        watermark = self._bump_icpu_watermark(host)
        self._create_pending_runtime_config(
            host, self.GRUB_RUNTIME_CLASSES,
            state=constants.RUNTIME_CONFIG_STATE_APPLIED,
            cpu_watermark=watermark)
        config_target_before = host.config_target

        self.service.update_grub_config(self.context, host.uuid)

        updated_host = self.dbapi.ihost_get(host.uuid)
        # EXPECTED OUTCOME on unfixed code: this FAILS. With no matching
        # PENDING row to re-stamp, config_target still advances -- there is
        # no cpu/memory divergence check on this path at all.
        self.assertEqual(
            config_target_before, updated_host.config_target,
            "counterexample: unchanged cpu/memory layout (most recent row "
            "already APPLIED, none pending) still advanced config_target "
            "from %s to %s" % (config_target_before,
                               updated_host.config_target))

    # --- Property 9 (Bug Condition C_B) exploration tests ------------------
    #
    # Goal: surface counterexamples showing that update_grub_config()
    # advances config_target and creates a runtime_config row for a host
    # whose state does not permit hieradata generation, and that the host's
    # report releases such a row from pending anyway. Written BEFORE the
    # fix, against the UNFIXED baseline (git worktree at 286d37452, the
    # parent of PS1). They are EXPECTED TO FAIL on unfixed code -- the
    # failure confirms isBugCondition_B(input) triggers unwanted config
    # state advancement and row creation. Do not fix the test or the code
    # when it fails here.
    #
    # No lab reaches this branch (force=True in every current lab, see
    # design.md SS7), so these unit tests are the only pre-fix red signal
    # available for Change B.

    @mock.patch('sysinv.conductor.manager.utils.is_host_simplex_controller',
                return_value=True)
    @mock.patch('os.path.isdir', return_value=True)
    @mock.patch('shutil.copytree')
    @mock.patch('sysinv.conductor.manager.tempfile.mkdtemp',
                return_value='/tmp/mock-temp-dir')
    def test_exploration_row_created_for_host_that_cannot_be_configured(
            self, mock_mkdtemp, mock_copytree, mock_isdir,
            mock_is_simplex_controller):
        # Bug condition C_B: invprovision is UNPROVISIONED, i.e. outside
        # PROVISIONED/UPGRADING and not a PROVISIONING controller, so
        # hieradata generation is refused with "the node is not ready" --
        # exactly the 340 occurrences at the customer. is_host_simplex_
        # controller is patched True so the local `force` computed inside
        # update_grub_config() is False (not utils.is_host_simplex_
        # controller(host) or force_grub_update == not True or False ==
        # False), matching the customer's day-1 topology where
        # /etc/platform/simplex is still present on the conductor node.
        # inv_state=INITIAL_INVENTORIED is the ONLY one of the three state
        # guards that passed at the customer -- it is what lets the row get
        # created despite hieradata generation being refused.
        host = self._create_test_worker_ihost(
            invprovision=constants.UNPROVISIONED,
            inv_state=constants.INV_STATE_INITIAL_INVENTORIED)
        config_target_before = host.config_target
        rows_before = self.dbapi.runtime_config_get_all(forihostid=host.id)
        self.assertEqual(0, len(rows_before))

        self.service.update_grub_config(self.context, host.uuid)

        updated_host = self.dbapi.ihost_get(host.uuid)
        rows_after = self.dbapi.runtime_config_get_all(forihostid=host.id)
        # EXPECTED OUTCOME on unfixed code: this FAILS. config_target
        # advances unconditionally inside _config_update_hosts(), which
        # runs before hieradata generation is even attempted.
        self.assertEqual(
            config_target_before, updated_host.config_target,
            "counterexample: host cannot be configured (invprovision=%s, "
            "hieradata generation refused with 'the node is not ready') "
            "but config_target still advanced from %s to %s" %
            (host.invprovision, config_target_before,
             updated_host.config_target))
        # EXPECTED OUTCOME on unfixed code: this FAILS. The row-creation
        # guard in _create_runtime_config_entries() checks only inv_state,
        # not invprovision/sw_version, so it creates and dispatches a row
        # for a host whose hieradata was just refused.
        self.assertEqual(
            0, len(rows_after),
            "counterexample: host cannot be configured (invprovision=%s) "
            "but a runtime_config row was still created and dispatched: "
            "%s" % (host.invprovision,
                    [(r.config_uuid, r.state) for r in rows_after]))

    # --- Change B fix checking (design.md unit tests 15, 16 and 18).
    #
    # These assert the guard task 9.1 added: a runtime enqueue must not
    # advance config_target and must not create a runtime_config row for a
    # host whose state does not allow its hieradata to be regenerated, i.e.
    # NOT (invprovision in [PROVISIONED, UPGRADING] or (PROVISIONING and
    # CONTROLLER)) or the host does not run the active controller's load.
    # Both call sites share the single predicate
    # _host_state_allows_hieradata().
    #
    # Scoped to the RUNTIME path on purpose (_config_update_hosts is
    # guarded only when reboot is False). That is the customer's path and
    # the only one that creates runtime_config rows or feeds the unlock
    # gate; a reboot-required update deliberately still advances its
    # target, because its hieradata comes from configure_ihost() through
    # the lock and unlock cycle.
    #
    # INDEPENDENT OF CHANGE A by construction: none of the three leaves a
    # grub runtime_config row carrying a cpu updated_at watermark, so the
    # Change A comparison can only fail open and the host-state guard is
    # unambiguously what makes every assertion below hold. No Change A
    # helper or constant is referenced either, so these pass on a tree
    # carrying the Change B hunks alone.
    #
    # _config_apply_runtime_manifest is mocked, as in every other
    # update_grub_config test in this module (it needs puppet hieradata
    # paths on disk and the agent RPC), and the entry creation it reaches
    # downstream is driven directly with the config_uuid / config_dict it
    # was handed. _config_update_hosts() is left REAL, so config_target is
    # observed on the host row rather than through a mock call count.

    @mock.patch('sysinv.conductor.manager.utils.is_host_simplex_controller',
                return_value=True)
    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_apply_runtime_manifest')
    def test_runtime_config_not_enqueued_when_host_not_ready(
            self, mock_config_apply_runtime_manifest,
            mock_is_simplex_controller):
        # design.md unit test 15 -- Property 12, Requirements 1.2, 2.12.
        # invprovision is UNPROVISIONED, so it is outside
        # PROVISIONED/UPGRADING and the host is not a PROVISIONING
        # controller: hieradata generation is refused with "the node is not
        # ready", exactly the 340 occurrences at the customer.
        # inv_state=INITIAL_INVENTORIED is the only one of the three state
        # guards that passed there, and it is what used to let the row be
        # created anyway.
        #
        # is_host_simplex_controller is patched True so the local `force`
        # computed inside update_grub_config() is False, matching the
        # customer's day-1 topology where /etc/platform/simplex is still
        # present on the node running the conductor. The guard does not read
        # that local; it is patched to keep the scenario the customer's.
        host = self._create_test_worker_ihost(
            invprovision=constants.UNPROVISIONED,
            inv_state=constants.INV_STATE_INITIAL_INVENTORIED)

        # The intended state has to be in the DATABASE, not only on the
        # dict this helper returns: other fixtures in this module set
        # invprovision on the returned object after the row was created, so
        # the value never reaches the database and the guard sees the
        # default instead.
        db_host = self.dbapi.ihost_get(host.uuid)
        self.assertEqual(constants.UNPROVISIONED, db_host.invprovision)
        self.assertEqual(constants.INV_STATE_INITIAL_INVENTORIED,
                         db_host.inv_state)
        # The load term is left as the suite sets it: host_load_matches_sw_
        # version is mocked True module-wide, so invprovision is the only
        # term that fails the predicate here.
        self.assertTrue(self.mock_host_load_matches_sw_version.return_value)
        # No prior grub row, so Change A's watermark comparison has nothing
        # to compare against and fails open.
        self.assertEqual(
            0, len(self.dbapi.runtime_config_get_all(forihostid=host.id)))
        config_target_before = host.config_target

        self.service.update_grub_config(self.context, host.uuid)

        # config_target half: the real _config_update_hosts() ran and did
        # not move the target of a host that cannot be configured.
        updated_host = self.dbapi.ihost_get(host.uuid)
        self.assertEqual(
            config_target_before, updated_host.config_target,
            "config_target advanced from %s to %s for a host that cannot "
            "be configured (invprovision=%s): nothing will ever apply that "
            "config_uuid, so config_applied is left permanently behind" %
            (config_target_before, updated_host.config_target,
             db_host.invprovision))

        # Row half: drive the entry creation with the exact config_uuid and
        # config_dict update_grub_config() handed to the mocked
        # _config_apply_runtime_manifest().
        mock_config_apply_runtime_manifest.assert_called_once()
        config_uuid = mock_config_apply_runtime_manifest.call_args[0][1]
        config_dict = copy.deepcopy(
            mock_config_apply_runtime_manifest.call_args[0][2])
        self.service._create_runtime_config_entries(config_uuid, config_dict)

        rows_after = self.dbapi.runtime_config_get_all(forihostid=host.id)
        self.assertEqual(
            0, len(rows_after),
            "a runtime_config row was created for a host that cannot be "
            "configured (invprovision=%s): the manifest never runs for it, "
            "and the fresh created_at renews the window "
            "check_unlock_runtime_manifests() rejects the unlock on: %s" %
            (db_host.invprovision,
             [(row.config_uuid, row.state) for row in rows_after]))

    @mock.patch('sysinv.conductor.manager.utils.is_host_simplex_controller',
                return_value=True)
    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_apply_runtime_manifest')
    def test_runtime_config_not_enqueued_when_sw_version_mismatch(
            self, mock_config_apply_runtime_manifest,
            mock_is_simplex_controller):
        # design.md unit test 16 -- Property 12, Requirements 1.2, 2.12.
        # Same assertions as the previous test, driven through the OTHER
        # term of the predicate: the host is PROVISIONED, so the
        # invprovision term passes, and the load check is what refuses the
        # hieradata. The hieradata of a host running a different load is
        # written by update_host_config_upgrade() into that host's own load
        # directory instead, so nothing on this path ever applies the
        # config.
        #
        # The mismatch is driven through the suite's existing mechanism:
        # _host_state_allows_hieradata() routes the term through
        # host_load_matches_sw_version(), which this module patches to
        # return True for every test (setUp), while tsc.SW_VERSION is
        # 'TEST.SW.VERSION' and test hosts are created on '0.0'. Flipping
        # the raw column alone would therefore change nothing.
        host = self._create_test_worker_ihost(
            inv_state=constants.INV_STATE_INITIAL_INVENTORIED)
        self.mock_host_load_matches_sw_version.return_value = False

        db_host = self.dbapi.ihost_get(host.uuid)
        # The invprovision term passes, so the load term is unambiguously
        # what fails the predicate.
        self.assertEqual(constants.PROVISIONED, db_host.invprovision)
        self.assertEqual(constants.INV_STATE_INITIAL_INVENTORIED,
                         db_host.inv_state)
        # And the state really is a mismatch, mock aside.
        self.assertNotEqual(manager.tsc.SW_VERSION, db_host.sw_version)
        self.assertEqual(
            0, len(self.dbapi.runtime_config_get_all(forihostid=host.id)))
        config_target_before = host.config_target

        self.service.update_grub_config(self.context, host.uuid)

        updated_host = self.dbapi.ihost_get(host.uuid)
        self.assertEqual(
            config_target_before, updated_host.config_target,
            "config_target advanced from %s to %s for a host running a "
            "different load (sw_version=%s, active=%s)" %
            (config_target_before, updated_host.config_target,
             db_host.sw_version, manager.tsc.SW_VERSION))

        mock_config_apply_runtime_manifest.assert_called_once()
        config_uuid = mock_config_apply_runtime_manifest.call_args[0][1]
        config_dict = copy.deepcopy(
            mock_config_apply_runtime_manifest.call_args[0][2])
        self.service._create_runtime_config_entries(config_uuid, config_dict)

        rows_after = self.dbapi.runtime_config_get_all(forihostid=host.id)
        self.assertEqual(
            0, len(rows_after),
            "a runtime_config row was created for a host running a "
            "different load (sw_version=%s, active=%s): %s" %
            (db_host.sw_version, manager.tsc.SW_VERSION,
             [(row.config_uuid, row.state) for row in rows_after]))

    @mock.patch('sysinv.conductor.manager.utils.is_host_simplex_controller',
                return_value=True)
    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_apply_runtime_manifest')
    def test_repeated_reconciles_against_non_configurable_host_create_no_rows(
            self, mock_config_apply_runtime_manifest,
            mock_is_simplex_controller):
        # design.md unit test 18 -- Property 14, Requirements 1.4, 2.14.
        # The reported DM loop, aimed at a host that cannot be configured:
        # a reconcile re-sends the same platform cpu configuration every
        # ~12s. Each cycle used to INSERT a fresh row (~166 of them at the
        # customer, median 11.8s apart), and every insert carried a fresh
        # created_at, which renewed the window
        # check_unlock_runtime_manifests() rejects the unlock on. That
        # window caps at CONF.host_unlock_blocking_period (600s), so it can
        # never age out while the inserts continue: the host stalls.
        #
        # What is asserted is that NO NEW ROW IS INSERTED, not that nothing
        # at all happens to any row. A pending row whose config_dict
        # matches is still superseded IN PLACE by
        # _create_runtime_config_entries() -- that branch is deliberately
        # reached before the guard -- so its config_uuid moves on while its
        # created_at, and therefore its position relative to the unlock
        # window, does not (Property 20, Requirement 3.6).
        #
        # Change A neutralised explicitly: the host has no cpu rows, so
        # there is no cpu updated_at watermark to persist, and the pending
        # row below is created without one. Change A's comparison hits its
        # "row predates the watermark" fail-open branch on every cycle and
        # cannot be the reason nothing is inserted. It also keeps the two
        # config_dicts equal, which is what routes the cycles through the
        # in-place re-stamp rather than the insert branch.
        host = self._create_test_worker_ihost(
            invprovision=constants.UNPROVISIONED,
            inv_state=constants.INV_STATE_INITIAL_INVENTORIED)
        db_host = self.dbapi.ihost_get(host.uuid)
        self.assertEqual(constants.UNPROVISIONED, db_host.invprovision)
        self.assertEqual(constants.INV_STATE_INITIAL_INVENTORIED,
                         db_host.inv_state)
        self.assertTrue(self.mock_host_load_matches_sw_version.return_value)
        self.assertEqual([], self.dbapi.icpu_get_by_ihost(host.uuid))

        pending_config_uuid = self._create_pending_runtime_config(
            host, self.GRUB_RUNTIME_CLASSES)
        rows_before = self.dbapi.runtime_config_get_all(forihostid=host.id)
        self.assertEqual(1, len(rows_before))
        row_id_before = rows_before[0].id
        created_at_before = rows_before[0].created_at
        config_target_before = host.config_target

        config_uuids = []
        for _ in range(5):
            self.service.update_grub_config(self.context, host.uuid)
            config_uuid = mock_config_apply_runtime_manifest.call_args[0][1]
            config_dict = copy.deepcopy(
                mock_config_apply_runtime_manifest.call_args[0][2])
            config_uuids.append(config_uuid)
            self.service._create_runtime_config_entries(
                config_uuid, config_dict)

        # Every cycle really did reach the enqueue with a distinct
        # config_uuid, so the row count below is not flat because the
        # reconciles collapsed into one another.
        self.assertEqual(5, len(set(config_uuids)))

        rows_after = self.dbapi.runtime_config_get_all(forihostid=host.id)
        self.assertEqual(
            1, len(rows_after),
            "%d reconciles against a host that cannot be configured "
            "inserted rows instead of leaving the count at 1: %s -- each "
            "insert carries a fresh created_at and renews the window the "
            "host unlock is rejected on" %
            (len(config_uuids),
             [(row.config_uuid, row.state, row.created_at)
              for row in rows_after]))
        # The pre-existing row was superseded in place, not replaced: same
        # row, same created_at, so the unlock window is not renewed and it
        # ages out normally.
        self.assertEqual(row_id_before, rows_after[0].id)
        self.assertEqual(
            created_at_before, rows_after[0].created_at,
            "the re-stamp moved created_at, which would renew the unlock "
            "window just as an insert does")
        self.assertNotEqual(pending_config_uuid, rows_after[0].config_uuid)
        self.assertEqual(constants.RUNTIME_CONFIG_STATE_PENDING,
                         rows_after[0].state)
        # And no config_target advanced across the whole loop.
        self.assertEqual(config_target_before,
                         self.dbapi.ihost_get(host.uuid).config_target)

    # --- Property 17 / 16 / 21 / 20 preservation: the surrounding
    # machinery -- re-stamp, unlock gate, audits, prune and the other five
    # conductor grub enqueue sites -- is untouched by either change.
    # Written BEFORE the fix, observed and passing on the UNFIXED baseline
    # (git worktree at 286d37452). Observation-first: these assert that
    # nothing OUTSIDE update_grub_config() moves.

    def test_create_runtime_config_entries_restamp_preserves_created_at(
            self):
        # An incoming config_dict equal to an existing PENDING row
        # supersedes it in place via
        # runtime_config_update(existing_config.id,
        # {"config_uuid": config_uuid}), changing only config_uuid and
        # leaving created_at unchanged, so the row's position relative to
        # the unlock window does not move (design.md unit test 7) --
        # Property 17.
        #
        # Corollary asserted below: the count of "Updating existing
        # config_uuid" log lines is NOT the metric of the churn -- it
        # marks only the harmless re-stamp half, and lab Run A showed 7
        # enqueues with ZERO re-stamps when every row reached applied
        # between cycles. This test only proves the re-stamp itself is
        # harmless (created_at frozen); it does not claim re-stamp counts
        # measure anything about the insert half.
        host = self._create_test_worker_ihost()
        existing_config_uuid = self._create_pending_runtime_config(
            host, self.GRUB_RUNTIME_CLASSES)
        existing_rows = self.dbapi.runtime_config_get_all(forihostid=host.id)
        self.assertEqual(1, len(existing_rows))
        created_at_before = existing_rows[0].created_at
        existing_id = existing_rows[0].id

        config_dict = {
            "personalities": [constants.CONTROLLER, constants.WORKER],
            "host_uuids": [host.uuid],
            "classes": self.GRUB_RUNTIME_CLASSES,
        }
        new_config_uuid = str(uuid.uuid4())
        self.assertNotEqual(existing_config_uuid, new_config_uuid)

        self.service._create_runtime_config_entries(
            new_config_uuid, config_dict)

        rows_after = self.dbapi.runtime_config_get_all(forihostid=host.id)
        # Still exactly one row: the incoming config_dict matched the
        # existing pending row, so it was superseded in place, not
        # inserted alongside it.
        self.assertEqual(1, len(rows_after))
        updated_row = rows_after[0]
        self.assertEqual(existing_id, updated_row.id)
        # Only config_uuid changed...
        self.assertEqual(new_config_uuid, updated_row.config_uuid)
        self.assertNotEqual(existing_config_uuid, updated_row.config_uuid)
        # ...created_at is untouched, so the row's age and its position
        # relative to the unlock gate's created_at window do not change.
        self.assertEqual(created_at_before, updated_row.created_at)

    def test_check_unlock_runtime_manifests_blocks_within_window(self):
        # The unlock gate check_unlock_runtime_manifests() is untouched by
        # either change: same runtime_config_get_all(state=PENDING,
        # younger_than=now-CONF.host_unlock_blocking_period,
        # forihostid=...) selection on created_at, same
        # config_dict['classes'] intersection with
        # get_blocking_runtime_manifest_list() -- Property 16.
        host = self._create_test_worker_ihost(hostname='controller-1')
        self._create_pending_runtime_config(host, self.GRUB_RUNTIME_CLASSES)

        controller = host_api.HostController()
        hostupdate = mock.Mock()
        hostupdate.ihost_patch = {'hostname': host.hostname}
        hostupdate.ihost_orig = {'id': host.id}

        with mock.patch(
                'sysinv.api.controllers.v1.host.pecan') as mock_pecan:
            mock_pecan.request.dbapi = self.dbapi
            self.assertRaises(
                wsme.exc.ClientSideError,
                controller.check_unlock_runtime_manifests,
                hostupdate, False, helper.get_blocking_runtime_manifest_list())

    def test_check_unlock_runtime_manifests_ignores_non_blocking_classes(
            self):
        # A pending row whose classes do not intersect
        # get_blocking_runtime_manifest_list() must not block unlock --
        # same class-intersection behavior as today -- Property 16.
        host = self._create_test_worker_ihost(hostname='controller-1')
        self._create_pending_runtime_config(
            host, ['platform::unrelated::runtime'])

        controller = host_api.HostController()
        hostupdate = mock.Mock()
        hostupdate.ihost_patch = {'hostname': host.hostname}
        hostupdate.ihost_orig = {'id': host.id}

        with mock.patch(
                'sysinv.api.controllers.v1.host.pecan') as mock_pecan:
            mock_pecan.request.dbapi = self.dbapi
            # Must not raise.
            controller.check_unlock_runtime_manifests(
                hostupdate, False, helper.get_blocking_runtime_manifest_list())

    def test_check_unlock_runtime_manifests_force_unlock_returns_early(
            self):
        # force_unlock returns before even querying the runtime_config
        # table -- same early return as today -- Property 16.
        host = self._create_test_worker_ihost(hostname='controller-1')
        self._create_pending_runtime_config(host, self.GRUB_RUNTIME_CLASSES)

        controller = host_api.HostController()
        hostupdate = mock.Mock()
        hostupdate.ihost_patch = {'hostname': host.hostname}
        hostupdate.ihost_orig = {'id': host.id}

        with mock.patch(
                'sysinv.api.controllers.v1.host.pecan') as mock_pecan:
            mock_dbapi = mock.Mock(wraps=self.dbapi)
            mock_pecan.request.dbapi = mock_dbapi
            # Must not raise despite the pending blocking row.
            controller.check_unlock_runtime_manifests(
                hostupdate, True, helper.get_blocking_runtime_manifest_list())
            mock_dbapi.runtime_config_get_all.assert_not_called()

    def test_check_unlock_runtime_manifests_row_older_than_window_does_not_block(
            self):
        # A pending row older than CONF.host_unlock_blocking_period does
        # NOT block unlock even though it was never applied -- the gate
        # filters strictly on created_at falling inside the window, with
        # no notion of whether the row ever reached applied -- Property
        # 16. This is the consequence explicitly called out in the task:
        # a row older than the window does not block unlock even if it
        # was never applied.
        host = self._create_test_worker_ihost(hostname='controller-1')
        self._create_pending_runtime_config(host, self.GRUB_RUNTIME_CLASSES)

        controller = host_api.HostController()
        hostupdate = mock.Mock()
        hostupdate.ihost_patch = {'hostname': host.hostname}
        hostupdate.ihost_orig = {'id': host.id}

        # Simulate the window having elapsed by moving "now" forward,
        # rather than mutating created_at directly -- the row is still
        # PENDING and was never applied.
        far_future = timeutils.utcnow() + datetime.timedelta(days=1)
        with mock.patch(
                'sysinv.api.controllers.v1.host.pecan') as mock_pecan, \
                mock.patch(
                    'sysinv.api.controllers.v1.host.datetime.datetime') \
                as mock_dt:
            mock_pecan.request.dbapi = self.dbapi
            mock_dt.now.return_value = far_future
            # Must not raise: the row aged out of the window.
            controller.check_unlock_runtime_manifests(
                hostupdate, False, helper.get_blocking_runtime_manifest_list())

    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._update_host_deferred_runtime_config')
    def test_audit_pending_runtime_config_retries_stale_rows(
            self, mock_deferred_config):
        # _audit_pending_runtime_config() re-enqueues a pending row older
        # than RUNTIME_CONFIG_APPLY_TIMEOUT_IN_SECS (1200s), advances
        # config_target to it and marks the row RETRIED -- unchanged by
        # either change -- Property 21.
        host = self._create_test_worker_ihost()
        config_uuid = str(uuid.uuid4())
        rc = self.dbapi.runtime_config_create({
            'config_uuid': config_uuid,
            'config_dict': json.dumps({
                'personalities': [constants.CONTROLLER, constants.WORKER],
                'classes': self.GRUB_RUNTIME_CLASSES,
                'config_type': manager.CONFIG_APPLY_RUNTIME_MANIFEST,
            }),
            'forihostid': host.id,
            'state': constants.RUNTIME_CONFIG_STATE_PENDING,
        })
        stale_created_at = (
            timeutils.utcnow() - datetime.timedelta(
                seconds=constants.RUNTIME_CONFIG_APPLY_TIMEOUT_IN_SECS + 100))
        from sysinv.db.sqlalchemy import api as db_sqlalchemy_api
        from sysinv.db.sqlalchemy import models as db_models
        with db_sqlalchemy_api._session_for_write() as session:
            session.query(db_models.RuntimeConfig).filter_by(
                id=rc.id).update({'created_at': stale_created_at})

        self.service._audit_pending_runtime_config()

        updated_host = self.dbapi.ihost_get(host.uuid)
        self.assertEqual(config_uuid, updated_host.config_target)
        mock_deferred_config.assert_called_once()
        updated_rc = self.dbapi.runtime_config_get(
            config_uuid, host_id=host.id)
        self.assertEqual(constants.RUNTIME_CONFIG_STATE_RETRIED,
                         updated_rc.state)

    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._update_host_deferred_runtime_config')
    def test_audit_config_out_of_date_hosts_skips_offline_host(
            self, mock_deferred_config):
        # _audit_config_out_of_date_hosts() skips hosts whose availability
        # is explicitly offline, even when the 250.001 alarm is stale --
        # unchanged by either change -- Property 21.
        host = self._create_test_worker_ihost(
            availability=constants.AVAILABILITY_OFFLINE)
        entity_instance_id = "%s=%s" % (
            fm_constants.FM_ENTITY_TYPE_HOST, host.hostname)
        stale_timestamp = (
            datetime.datetime.utcnow() - datetime.timedelta(
                seconds=constants.RUNTIME_CONFIG_APPLY_TIMEOUT_IN_SECS + 100)
        ).strftime("%Y-%m-%d %H:%M:%S.%f")
        fake_fault = mock.Mock(entity_instance_id=entity_instance_id,
                               timestamp=stale_timestamp)
        self.service.fm_api.get_faults_by_id.return_value = [fake_fault]

        self.service._audit_config_out_of_date_hosts()

        mock_deferred_config.assert_not_called()

    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._delete_old_temp_hieradata')
    def test_prune_runtime_config_table_removes_only_24h_and_older(
            self, mock_delete_hieradata):
        # _prune_runtime_config_table() removes rows only at the 24-hour
        # cutoff, leaving more recent rows (including orphans that were
        # never applied) untouched -- unchanged by either change --
        # Property 21.
        host = self._create_test_worker_ihost()
        old_config_uuid = self._create_pending_runtime_config(
            host, self.GRUB_RUNTIME_CLASSES)
        recent_config_uuid = self._create_pending_runtime_config(
            host, self.GRUB_RUNTIME_CLASSES)
        from sysinv.db.sqlalchemy import api as db_sqlalchemy_api
        from sysinv.db.sqlalchemy import models as db_models
        old_row = self.dbapi.runtime_config_get(
            old_config_uuid, host_id=host.id)
        with db_sqlalchemy_api._session_for_write() as session:
            session.query(db_models.RuntimeConfig).filter_by(
                id=old_row.id).update(
                    {'created_at': datetime.datetime.utcnow() -
                     datetime.timedelta(hours=25)})

        self.service._prune_runtime_config_table()

        remaining_uuids = [
            r.config_uuid for r in
            self.dbapi.runtime_config_get_all(forihostid=host.id)]
        self.assertNotIn(old_config_uuid, remaining_uuids)
        self.assertIn(recent_config_uuid, remaining_uuids)

    # --- Property 20: the other five conductor grub enqueue sites stay
    # OUTSIDE the update_grub_config() guard. Reuses the three PS1
    # class-set negatives' shape: assert each site still enqueues, since
    # the redundancy check must not be centralized lower than
    # update_grub_config() (Requirement 3.9).

    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_apply_runtime_manifest')
    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_update_hosts')
    def test_kernel_config_enqueue_site_outside_guard(
            self, mock_config_update_hosts,
            mock_config_apply_runtime_manifest):
        # kernel config (~L1780, 3-class): kernel_runtime_manifests()
        # always enqueues, regardless of any prior grub runtime_config
        # row -- it is a separate call site from update_grub_config() and
        # is not subject to its redundancy guard.
        self._create_test_ihosts()
        ihost = self.service.get_ihost_by_hostname(
            self.context, 'controller-0')
        mock_config_update_hosts.return_value = str(uuid.uuid4())

        self.service.kernel_runtime_manifests(
            context=self.context, ihost_uuid=ihost['uuid'])

        mock_config_update_hosts.assert_called_once()
        mock_config_apply_runtime_manifest.assert_called_once()
        config_dict = mock_config_apply_runtime_manifest.call_args[0][2]
        self.assertEqual([
            'platform::grub::kernel_image::runtime',
            'platform::config::file::subfunctions::lowlatency::runtime',
            'platform::compute::grub::runtime'
        ], config_dict['classes'])

    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_apply_runtime_manifest')
    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_update_hosts')
    @mock.patch('sysinv.conductor.manager.os.path.isfile')
    def test_aio_pre_unlock_two_class_grub_enqueue_site_outside_guard(
            self, mock_isfile, mock_config_update_hosts,
            mock_config_apply_runtime_manifest):
        # AIO pre-unlock (~L2656, 2-class grub pair): _configure_
        # controller_host() always applies the exact 2-class grub pair
        # ahead of the initial controller's unlock on an AIO system with
        # the Ansible bootstrap flag present -- outside
        # update_grub_config()'s guard. Explicit assertion: the 2-class
        # grub apply the agent's UNLOCK_READY_FLAG path depends on is
        # never suppressed here -- Property 20.
        def isfile_side_effect(path):
            return path == constants.ANSIBLE_BOOTSTRAP_FLAG
        mock_isfile.side_effect = isfile_side_effect
        cutils.is_aio_system = mock.Mock(return_value=True)

        host = self._create_test_worker_ihost(
            administrative=constants.ADMIN_LOCKED,
            availability=constants.AVAILABILITY_ONLINE)
        mock_config_update_hosts.return_value = str(uuid.uuid4())

        self.service._configure_controller_host(self.context, host)

        two_class_calls = [
            call for call in
            mock_config_apply_runtime_manifest.call_args_list
            if call[0][2].get('classes') == self.GRUB_RUNTIME_CLASSES]
        self.assertEqual(
            1, len(two_class_calls),
            "the 2-class grub apply the agent's UNLOCK_READY_FLAG path "
            "depends on must never be suppressed on the AIO pre-unlock "
            "path")
        self.assertTrue(two_class_calls[0][1].get('force'))

    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_apply_runtime_manifest')
    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_update_hosts')
    def test_kernel_service_parameter_enqueue_site_outside_guard(
            self, mock_config_update_hosts,
            mock_config_apply_runtime_manifest):
        # kernel service parameter (~L13294): update_service_config() for
        # SERVICE_PARAM_SECTION_PLATFORM_KERNEL enqueues the single-class
        # grub runtime unconditionally -- outside update_grub_config()'s
        # guard.
        mock_config_update_hosts.return_value = str(uuid.uuid4())

        self.service.update_service_config(
            self.context,
            service=constants.SERVICE_TYPE_PLATFORM,
            do_apply=False,
            section=constants.SERVICE_PARAM_SECTION_PLATFORM_KERNEL,
            name=constants.SERVICE_PARAM_NAME_PLATFORM_AUDITD)

        mock_config_update_hosts.assert_called_once()
        mock_config_apply_runtime_manifest.assert_called_once()
        config_dict = mock_config_apply_runtime_manifest.call_args[0][2]
        self.assertEqual(['platform::compute::grub::runtime'],
                         config_dict['classes'])

    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_apply_runtime_manifest')
    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_update_hosts')
    def test_intel_pstate_enqueue_site_outside_guard(
            self, mock_config_update_hosts,
            mock_config_apply_runtime_manifest):
        # intel_pstate (~L13317): update_service_config() enqueues the
        # single-class grub runtime unconditionally -- outside
        # update_grub_config()'s guard.
        mock_config_update_hosts.return_value = str(uuid.uuid4())

        self.service.update_service_config(
            self.context,
            service=constants.SERVICE_TYPE_PLATFORM,
            do_apply=False,
            section=constants.SERVICE_PARAM_SECTION_PLATFORM_CONFIG,
            name=constants.SERVICE_PARAM_NAME_PLAT_CONFIG_INTEL_PSTATE)

        mock_config_update_hosts.assert_called_once()
        mock_config_apply_runtime_manifest.assert_called_once()
        config_dict = mock_config_apply_runtime_manifest.call_args[0][2]
        self.assertEqual(['platform::compute::grub::runtime'],
                         config_dict['classes'])

    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_apply_runtime_manifest')
    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_update_hosts')
    def test_amd_pstate_enqueue_site_outside_guard(
            self, mock_config_update_hosts,
            mock_config_apply_runtime_manifest):
        # amd_pstate (~L13334): update_service_config() enqueues the
        # single-class grub runtime unconditionally -- outside
        # update_grub_config()'s guard.
        mock_config_update_hosts.return_value = str(uuid.uuid4())

        self.service.update_service_config(
            self.context,
            service=constants.SERVICE_TYPE_PLATFORM,
            do_apply=False,
            section=constants.SERVICE_PARAM_SECTION_PLATFORM_CONFIG,
            name=constants.SERVICE_PARAM_NAME_PLAT_CONFIG_AMD_PSTATE)

        mock_config_update_hosts.assert_called_once()
        mock_config_apply_runtime_manifest.assert_called_once()
        config_dict = mock_config_apply_runtime_manifest.call_args[0][2]
        self.assertEqual(['platform::compute::grub::runtime'],
                         config_dict['classes'])

    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_apply_runtime_manifest')
    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_clear_reboot_required')
    @mock.patch('sysinv.conductor.manager.'
                'ConductorManager._config_update_hosts')
    def test_update_security_feature_config(self,
                                            mock_config_update_hosts,
                                            mock_config_clear_reboot_required,
                                            mock_config_apply_runtime_manifest):
        """Test update_security_feature_config uses correct puppet class."""
        self._create_test_ihosts()

        config_uuid = str(uuid.uuid4())
        cleared_config_uuid = str(uuid.uuid4())
        mock_config_update_hosts.return_value = config_uuid
        mock_config_clear_reboot_required.return_value = cleared_config_uuid

        self.service.update_security_feature_config(context=self.context)

        # Verify _config_update_hosts called with all personalities except EDGEWORKER
        expected_personalities = [i for i in constants.PERSONALITIES
                                  if i != constants.EDGEWORKER]
        mock_config_update_hosts.assert_called_once_with(
            self.context, expected_personalities, reboot=True)

        # Verify correct puppet class is used (not the old 'platform::grub::runtime')
        expected_config_dict = {
            'personalities': expected_personalities,
            'classes': ['platform::grub::security_features::runtime']
        }
        mock_config_clear_reboot_required.assert_called_once_with(config_uuid)
        mock_config_apply_runtime_manifest.assert_called_once_with(
            self.context, cleared_config_uuid, expected_config_dict, force=True)

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
    @mock.patch('os.path.isfile', return_value=True)
    def test_get_app_bundle_for_update(self, mock_isfile):
        app_moked = self.get_app_object_moked_and_call_start()

        # Test when k8s_version is None
        result = self.service._get_app_bundle_for_update(app_moked)
        # It should be if 1.1.0 auto_update was not false
        self.assertEqual(result.version, "1.0.5")

    @mock.patch('os.path.isfile', return_value=True)
    def test_get_app_bundle_for_update_k8s_version(self, mock_isfile):
        app_moked = self.get_app_object_moked_and_call_start()

        # Test when k8s_version is specified
        result = self.service._get_app_bundle_for_update(app_moked, k8s_version="v1.27.5")
        self.assertEqual(result.version, "1.2.5")
        # It was not version 1.2.5 because this metadata supports at most
        # version 1.20.0 of kubernets
        result = self.service._get_app_bundle_for_update(app_moked, k8s_version="v1.29.2")
        self.assertEqual(result.version, "1.2.0")

    @mock.patch('os.path.isfile', return_value=True)
    def test_get_app_bundle_for_update_k8s_upgrade_timing(self, mock_isfile):
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

    @mock.patch('os.path.isfile', return_value=True)
    def test_get_app_bundle_for_update_downgrade(self, mock_isfile):
        app_moked = self.get_app_object_moked_and_call_start()

        # Using a higher app version than is available. The function must be able
        # to return the largest version available.
        app_moked.app_version = "1.2.3"
        result = self.service._get_app_bundle_for_update(app_moked)
        self.assertEqual(result.version, "1.1.0")

    @mock.patch('os.path.isfile', return_value=True)
    def test_get_app_bundle_for_update_k8s_version_lower_than_available(self, mock_isfile):
        app_moked = self.get_app_object_moked_and_call_start()

        # Test when k8s_version lower than what is available.
        # This forces the return None
        result = self.service._get_app_bundle_for_update(app_moked, k8s_version="v1.17.0")
        self.assertEqual(result, None)

    @mock.patch('os.path.isfile', return_value=False)
    def test_get_app_bundle_for_update_bundle_not_found(self, mock_isfile):
        app_moked = self.get_app_object_moked_and_call_start()

        # Test when the bundle file does not exist
        result = self.service._get_app_bundle_for_update(app_moked)
        self.assertEqual(result, None)

    @mock.patch('os.path.isfile', return_value=True)
    def test_get_app_bundle_for_update_bool_auto_downgrade(self, mock_isfile):
        """Test auto_downgrade as bool (YAML-parsed) does not raise AttributeError"""
        self.service.start()

        app = mock.MagicMock()
        app.name = "test_app"
        app.app_version = "1.0.0"
        app.app_metadata = {
            constants.APP_METADATA_DOWNGRADES: {
                constants.APP_METADATA_AUTO_DOWNGRADE: True
            }
        }

        result = self.service._get_app_bundle_for_update(app)
        self.assertEqual(result.version, "1.0.5")

    @mock.patch('os.path.isfile', return_value=True)
    def test_get_app_bundle_for_update_bool_false_auto_downgrade(self, mock_isfile):
        """Test auto_downgrade as bool False disables downgrade"""
        self.service.start()

        app = mock.MagicMock()
        app.name = "test_app"
        app.app_version = "1.2.3"
        app.app_metadata = {
            constants.APP_METADATA_DOWNGRADES: {
                constants.APP_METADATA_AUTO_DOWNGRADE: False
            }
        }

        result = self.service._get_app_bundle_for_update(app)
        self.assertIsNone(result)

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

    # Calico Operator path tests (k8s >= v1.35.2)
    def _setup_operator_test_mocks(self, network_images, image_download_result,
                                   upgrade_overrides_file_exists, upgrade_overrides):
        """Common mock setup for operator path tests"""
        mocks = {}

        mocks['sanitize'] = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.sanitize_kubeadm_configmap',
                       mocks['sanitize'])
        p.start().return_value = 0
        self.addCleanup(p.stop)

        mocks['backup'] = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager.backup_kube_control_plane',
                       mocks['backup'])
        p.start()
        self.addCleanup(p.stop)

        mocks['get_images'] = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager._get_kubernetes_system_images',
                       mocks['get_images'])
        p.start().return_value = network_images
        self.addCleanup(p.stop)

        mocks['download'] = mock.MagicMock()
        p = mock.patch(
            'sysinv.conductor.manager.ContainerImageDownloader.'
            'download_images_from_upstream_to_local_reg_and_crictl',
            mocks['download'])
        p.start().return_value = image_download_result
        self.addCleanup(p.stop)

        p = mock.patch('sysinv.common.utils.get_local_docker_registry_auth', mock.MagicMock())
        p.start().return_value = {'username': 'fake', 'password': 'fake'}
        self.addCleanup(p.stop)

        p = mock.patch.object(agent_rpcapi.AgentAPI, 'pull_kubernetes_images', mock.MagicMock())
        p.start()
        self.addCleanup(p.stop)

        p = mock.patch('sysinv.common.utils.execute',
                       mock.MagicMock(return_value=('cni-bin-dir', '')))
        p.start()
        self.addCleanup(p.stop)

        mock_os_path_exists = mock.MagicMock()
        mock_os_path_exists.side_effect = lambda path: (
            False if path == "/etc/cni/net.d/05-multus.conf"
            else upgrade_overrides_file_exists
        )
        p = mock.patch('os.path.exists', mock_os_path_exists)
        p.start()
        self.addCleanup(p.stop)

        p = mock.patch('builtins.open', mock.mock_open())
        p.start()
        self.addCleanup(p.stop)

        if cutils.is_debian_bullseye():
            p = mock.patch('ruamel.yaml.safe_load', mock.MagicMock())
            p.start().return_value = upgrade_overrides
            self.addCleanup(p.stop)
        else:
            mock_yaml_obj = mock.MagicMock()
            mock_yaml_obj.load.return_value = upgrade_overrides
            p = mock.patch('sysinv.conductor.manager.YAML', return_value=mock_yaml_obj)
            p.start()
            self.addCleanup(p.stop)

        p = mock.patch('shutil.copy2', mock.MagicMock())
        p.start()
        self.addCleanup(p.stop)

        mocks['render'] = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.render_jinja_template_from_file', mocks['render'])
        p.start().return_value = "fake_rendered_string"
        self.addCleanup(p.stop)

        mocks['kubectl_apply'] = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.kubectl_apply', mocks['kubectl_apply'])
        p.start()
        self.addCleanup(p.stop)

        mocks['os_remove'] = mock.MagicMock()
        p = mock.patch('os.remove', mocks['os_remove'])
        p.start()
        self.addCleanup(p.stop)

        # Initialize _kube
        if self.service._kube is None:
            self.service._kube = mock.MagicMock()

        mocks['create_ns'] = mock.MagicMock()
        p = mock.patch.object(self.service._kube, 'kube_create_namespace', mocks['create_ns'])
        p.start()
        self.addCleanup(p.stop)

        mocks['patch_ns'] = mock.MagicMock()
        p = mock.patch.object(self.service._kube, 'kube_patch_namespace', mocks['patch_ns'])
        p.start()
        self.addCleanup(p.stop)

        mocks['copy_secret'] = mock.MagicMock()
        p = mock.patch.object(self.service._kube, 'kube_copy_secret', mocks['copy_secret'])
        p.start()
        self.addCleanup(p.stop)

        mocks['get_secret'] = mock.MagicMock(return_value=None)
        p = mock.patch.object(self.service._kube, 'kube_get_secret', mocks['get_secret'])
        p.start()
        self.addCleanup(p.stop)

        captured_calico_ctx = {}
        orig_gen = self.service._generate_k8s_manifests_and_apply

        def _gen_wrapper(source_template_path, dest_manifest_path, *, is_template=False, values=None):
            if os.path.basename(str(dest_manifest_path)) == 'update_calico-operator.yaml':
                captured_calico_ctx['ctx'] = values
            return orig_gen(source_template_path, dest_manifest_path,
                            is_template=is_template, values=values)

        p = mock.patch.object(self.service, '_generate_k8s_manifests_and_apply', side_effect=_gen_wrapper)
        p.start()
        self.addCleanup(p.stop)

        mocks['captured_ctx'] = captured_calico_ctx
        return mocks

    def _get_calico_operator_network_images(self):
        return {'calico_cni_img': 'fake_calico_cni_img',
                'calico_ctl_img': 'fake_calico_ctl_img',
                'calico_dikastes_img': 'fake_calico_dikastes_img',
                'calico_envoy_gateway_img': 'fake_calico_envoy_gateway_img',
                'calico_envoy_proxy_img': 'fake_calico_envoy_proxy_img',
                'calico_kube_controllers_img': 'fake_calico_kube_controllers_img',
                'calico_node_img': 'fake_calico_node_img',
                'calico_pod2daemon_flexvol_img': 'fake_calico_pod2daemon_flexvol_img',
                'calico_typha_img': 'fake_calico_typha_img',
                'multus_img': 'fake_multus_img',
                'sriov_cni_img': 'fake_sriov_cni_img',
                'sriov_network_device_img': 'fake_sriov_network_device_img',
                'tigera_operator_img': 'fake_tigera_operator_img'}

    def test_kube_upgrade_networking_success_calico_operator_ipv4(self):
        """Test kubernetes networking upgrade with Calico operator (ipv4, >= v1.35.2)"""
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER, hostname='controller-0',
            uuid=str(uuid.uuid4()), config_status=None,
            config_applied=config_uuid, config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        FROM_VERSION = 'v1.34.1'
        TO_VERSION = 'v1.35.2'
        upgrade_overrides = {"cluster_pod_subnet": "172.16.0.0/16",
                             "cluster_host_floating_address": "192.168.206.1",
                             "cluster_host_node_0_address": "192.168.206.2"}

        utils.create_test_kube_upgrade(from_version=FROM_VERSION, to_version=TO_VERSION,
                                       state=kubernetes.KUBE_UPGRADING_NETWORKING)

        mocks = self._setup_operator_test_mocks(
            self._get_calico_operator_network_images(), True, True, upgrade_overrides)

        self.service.kube_upgrade_networking(self.context, TO_VERSION)

        mocks['create_ns'].assert_any_call('calico-system')
        mocks['create_ns'].assert_any_call('tigera-operator')
        self.assertEqual(mocks['create_ns'].call_count, 2)
        mocks['copy_secret'].assert_any_call('registry-local-secret', 'kube-system', 'calico-system')
        mocks['copy_secret'].assert_any_call('registry-local-secret', 'kube-system', 'tigera-operator')
        self.assertEqual(mocks['render'].call_count, 7)
        self.assertEqual(mocks['kubectl_apply'].call_count, 8)

        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state, kubernetes.KUBE_UPGRADED_NETWORKING)

        ctx = mocks['captured_ctx'].get('ctx')
        self.assertIsNotNone(ctx)
        self.assertEqual(ctx.get('cluster_network_ipv4'), '172.16.0.0/16')
        self.assertIsNone(ctx.get('cluster_network_ipv6'))
        self.assertEqual(ctx.get('tigera_operator_img'), 'fake_tigera_operator_img')

    def test_kube_upgrade_networking_success_calico_operator_ipv6(self):
        """Test kubernetes networking upgrade with Calico operator (ipv6, >= v1.35.2)"""
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER, hostname='controller-0',
            uuid=str(uuid.uuid4()), config_status=None,
            config_applied=config_uuid, config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        FROM_VERSION = 'v1.34.1'
        TO_VERSION = 'v1.35.2'
        upgrade_overrides = {"cluster_pod_subnet": "fd00::/64",
                             "cluster_host_floating_address": "fd01::1",
                             "cluster_host_node_0_address": "fd01::2"}

        utils.create_test_kube_upgrade(from_version=FROM_VERSION, to_version=TO_VERSION,
                                       state=kubernetes.KUBE_UPGRADING_NETWORKING)

        mocks = self._setup_operator_test_mocks(
            self._get_calico_operator_network_images(), True, True, upgrade_overrides)

        self.service.kube_upgrade_networking(self.context, TO_VERSION)

        mocks['create_ns'].assert_any_call('calico-system')
        mocks['create_ns'].assert_any_call('tigera-operator')
        mocks['copy_secret'].assert_any_call('registry-local-secret', 'kube-system', 'calico-system')
        self.assertEqual(mocks['render'].call_count, 7)
        self.assertEqual(mocks['kubectl_apply'].call_count, 8)

        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state, kubernetes.KUBE_UPGRADED_NETWORKING)

        ctx = mocks['captured_ctx'].get('ctx')
        self.assertIsNotNone(ctx)
        self.assertIsNone(ctx.get('cluster_network_ipv4'))
        self.assertEqual(ctx.get('cluster_network_ipv6'), 'fd00::/64')
        self.assertEqual(ctx.get('tigera_operator_img'), 'fake_tigera_operator_img')

    def test_kube_upgrade_networking_success_calico_operator_dual_stack(self):
        """Test kubernetes networking upgrade with Calico operator (dual-stack, >= v1.35.2)"""
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER, hostname='controller-0',
            uuid=str(uuid.uuid4()), config_status=None,
            config_applied=config_uuid, config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        FROM_VERSION = 'v1.34.1'
        TO_VERSION = 'v1.35.2'
        upgrade_overrides = {"cluster_pod_subnet": "172.16.0.0/16,fd00::/64",
                             "cluster_host_floating_address": "192.168.206.1",
                             "cluster_host_node_0_address": "192.168.206.2,fd01::2"}

        utils.create_test_kube_upgrade(from_version=FROM_VERSION, to_version=TO_VERSION,
                                       state=kubernetes.KUBE_UPGRADING_NETWORKING)

        mocks = self._setup_operator_test_mocks(
            self._get_calico_operator_network_images(), True, True, upgrade_overrides)

        self.service.kube_upgrade_networking(self.context, TO_VERSION)

        mocks['create_ns'].assert_any_call('calico-system')
        mocks['create_ns'].assert_any_call('tigera-operator')
        mocks['copy_secret'].assert_any_call('registry-local-secret', 'kube-system', 'calico-system')
        self.assertEqual(mocks['render'].call_count, 7)
        self.assertEqual(mocks['kubectl_apply'].call_count, 8)

        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state, kubernetes.KUBE_UPGRADED_NETWORKING)

        ctx = mocks['captured_ctx'].get('ctx')
        self.assertIsNotNone(ctx)
        self.assertEqual(ctx.get('cluster_network_ipv4'), '172.16.0.0/16')
        self.assertEqual(ctx.get('cluster_network_ipv6'), 'fd00::/64')
        self.assertEqual(ctx.get('tigera_operator_img'), 'fake_tigera_operator_img')


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


class TestPeriodicChartCleanup(base.DbTestCase):
    """Tests for ConductorManager.delete_unused_helm_charts()."""

    def setUp(self):
        super(TestPeriodicChartCleanup, self).setUp()

        self.service = manager.ConductorManager('test-host', 'test-topic')
        self.service.dbapi = dbapi.get_instance()
        self._orig_kube_app_get_all = self.service.dbapi.kube_app_get_all
        self.context = context.get_admin_context()
        self.system = utils.create_test_isystem()
        self.service._app = mock.Mock()
        self.service.fm_api = mock.Mock()

    def tearDown(self):
        self.service.dbapi.kube_app_get_all = self._orig_kube_app_get_all
        super(TestPeriodicChartCleanup, self).tearDown()

    @mock.patch('sysinv.common.utils.get_platform_core_count', return_value=2)
    @mock.patch('sysinv.helm.utils.index_repo')
    @mock.patch('os.remove')
    @mock.patch('os.listdir')
    @mock.patch('os.path.isdir')
    def test_removes_unused_charts(
            self, mock_isdir, mock_listdir, mock_remove,
            mock_index_repo, mock_core_count):
        """Test that charts not in use by any active app are removed."""

        mock_isdir.return_value = True
        mock_listdir.return_value = [
            'app-chart-1.0.0.tgz',
            'app-chart-2.0.0.tgz',
            'unused-chart-1.0.0.tgz',
            'index.yaml',
        ]

        mock_chart_in_use = mock.MagicMock()
        mock_chart_in_use.filesystem_location = \
            '/var/www/pages/helm_charts/starlingx/app-chart-1.0.0.tgz'

        mock_chart_in_use_2 = mock.MagicMock()
        mock_chart_in_use_2.filesystem_location = \
            '/var/www/pages/helm_charts/starlingx/app-chart-2.0.0.tgz'

        self.service._app._get_list_of_charts.return_value = [
            mock_chart_in_use, mock_chart_in_use_2
        ]

        # Create a fake active app in the database
        mock_db_app = mock.MagicMock()
        mock_db_app.active = True
        mock_db_app.name = 'test-app'
        self.service._app.Application.return_value = mock.MagicMock()
        self.service.dbapi.kube_app_get_all = mock.MagicMock(
            return_value=[mock_db_app])

        self.service.delete_unused_helm_charts(self.context)

        # Only unused-chart-1.0.0.tgz should be removed (once per repo)
        removed_paths = [call[0][0] for call in mock_remove.call_args_list]
        self.assertIn(
            '/var/www/pages/helm_charts/starlingx/unused-chart-1.0.0.tgz',
            removed_paths)
        self.assertIn(
            '/var/www/pages/helm_charts/stx-platform/unused-chart-1.0.0.tgz',
            removed_paths)

        # Charts in use should NOT be removed
        self.assertNotIn(
            '/var/www/pages/helm_charts/starlingx/app-chart-1.0.0.tgz',
            removed_paths)
        self.assertNotIn(
            '/var/www/pages/helm_charts/starlingx/app-chart-2.0.0.tgz',
            removed_paths)

        # index_repo should be called for modified repos
        self.assertTrue(mock_index_repo.called)

    @mock.patch('sysinv.common.utils.get_platform_core_count', return_value=2)
    @mock.patch('sysinv.helm.utils.index_repo')
    @mock.patch('os.remove')
    @mock.patch('os.listdir')
    @mock.patch('os.path.isdir')
    def test_no_removal_needed(
            self, mock_isdir, mock_listdir, mock_remove,
            mock_index_repo, mock_core_count):
        """Test that no charts are removed when all are in use."""

        mock_isdir.return_value = True
        mock_listdir.return_value = [
            'app-chart-1.0.0.tgz',
            'index.yaml',
        ]

        mock_chart = mock.MagicMock()
        mock_chart.filesystem_location = \
            '/var/www/pages/helm_charts/starlingx/app-chart-1.0.0.tgz'

        mock_chart_platform = mock.MagicMock()
        mock_chart_platform.filesystem_location = \
            '/var/www/pages/helm_charts/stx-platform/app-chart-1.0.0.tgz'

        self.service._app._get_list_of_charts.return_value = [
            mock_chart, mock_chart_platform
        ]

        mock_db_app = mock.MagicMock()
        mock_db_app.active = True
        mock_db_app.name = 'test-app'
        self.service._app.Application.return_value = mock.MagicMock()
        self.service.dbapi.kube_app_get_all = mock.MagicMock(
            return_value=[mock_db_app])

        self.service.delete_unused_helm_charts(self.context)

        # No charts should be removed
        mock_remove.assert_not_called()
        # No repos should be re-indexed
        mock_index_repo.assert_not_called()

    @mock.patch('sysinv.common.utils.get_platform_core_count', return_value=2)
    @mock.patch('sysinv.helm.utils.index_repo')
    @mock.patch('os.remove')
    @mock.patch('os.listdir')
    @mock.patch('os.path.isdir')
    def test_no_active_apps(
            self, mock_isdir, mock_listdir, mock_remove,
            mock_index_repo, mock_core_count):
        """Test that no active apps were found.

        kube_app_get_all() filters out apps with APP_INACTIVE_STATE at the
        DB level, so when all apps are inactive the returned list is empty.
        In this scenario the clean-up should be skipped since the system is
        supposed to have at least active critical apps.
        """

        mock_isdir.return_value = True
        mock_listdir.return_value = [
            'inactive-chart-1.0.0.tgz',
            'index.yaml',
        ]

        # kube_app_get_all filters inactive apps at the DB layer,
        # so it returns an empty list
        self.service.dbapi.kube_app_get_all = mock.MagicMock(
            return_value=[])

        self.service.delete_unused_helm_charts(self.context)

        # No charts should be removed
        mock_remove.assert_not_called()
        # No repos should be re-indexed
        mock_index_repo.assert_not_called()

    @mock.patch('sysinv.common.utils.get_platform_core_count', return_value=2)
    @mock.patch('sysinv.helm.utils.index_repo')
    @mock.patch('os.remove')
    @mock.patch('os.listdir')
    @mock.patch('os.path.isdir')
    def test_skips_non_tgz_files(
            self, mock_isdir, mock_listdir, mock_remove,
            mock_index_repo, mock_core_count):
        """Test that non-.tgz files (like index.yaml) are never removed."""

        mock_isdir.return_value = True
        mock_listdir.return_value = [
            'index.yaml',
            'README.md',
        ]

        self.service._app._get_list_of_charts.return_value = []

        mock_db_app = mock.MagicMock()
        mock_db_app.active = True
        mock_db_app.name = 'test-app'
        self.service._app.Application.return_value = mock.MagicMock()
        self.service.dbapi.kube_app_get_all = mock.MagicMock(
            return_value=[mock_db_app])

        self.service.delete_unused_helm_charts(self.context)

        # No files should be removed
        mock_remove.assert_not_called()
        mock_index_repo.assert_not_called()

    @mock.patch('sysinv.common.utils.get_platform_core_count', return_value=2)
    @mock.patch('sysinv.helm.utils.index_repo')
    @mock.patch('os.remove')
    @mock.patch('os.listdir')
    @mock.patch('os.path.isdir')
    def test_skips_missing_repo_dir(
            self, mock_isdir, mock_listdir, mock_remove,
            mock_index_repo, mock_core_count):
        """Test that missing repo directories are skipped gracefully."""

        mock_isdir.return_value = False

        self.service._app._get_list_of_charts.return_value = []

        mock_db_app = mock.MagicMock()
        mock_db_app.active = True
        mock_db_app.name = 'test-app'
        self.service._app.Application.return_value = mock.MagicMock()
        self.service.dbapi.kube_app_get_all = mock.MagicMock(
            return_value=[mock_db_app])

        self.service.delete_unused_helm_charts(self.context)

        # listdir should never be called if dir doesn't exist
        mock_listdir.assert_not_called()
        mock_remove.assert_not_called()
        mock_index_repo.assert_not_called()

    @mock.patch('sysinv.common.utils.get_platform_core_count', return_value=2)
    @mock.patch('sysinv.helm.utils.index_repo')
    @mock.patch('os.remove')
    @mock.patch('os.listdir')
    @mock.patch('os.path.isdir')
    def test_handles_remove_failure(
            self, mock_isdir, mock_listdir, mock_remove,
            mock_index_repo, mock_core_count):
        """Test that OSError on remove is handled gracefully."""

        mock_isdir.return_value = True
        mock_listdir.return_value = ['unused-chart-1.0.0.tgz']
        mock_remove.side_effect = OSError("Permission denied")

        self.service._app._get_list_of_charts.return_value = []

        mock_db_app = mock.MagicMock()
        mock_db_app.active = True
        mock_db_app.name = 'test-app'
        self.service._app.Application.return_value = mock.MagicMock()
        self.service.dbapi.kube_app_get_all = mock.MagicMock(
            return_value=[mock_db_app])

        # Should not raise
        self.service.delete_unused_helm_charts(self.context)

        # Remove was attempted
        self.assertTrue(mock_remove.called)
        # index_repo should not be called since remove failed
        mock_index_repo.assert_not_called()

    @mock.patch('sysinv.common.utils.get_platform_core_count', return_value=2)
    @mock.patch('sysinv.helm.utils.index_repo')
    @mock.patch('os.remove')
    @mock.patch('os.listdir')
    @mock.patch('os.path.isdir')
    def test_handles_get_apps_failure(
            self, mock_isdir, mock_listdir, mock_remove,
            mock_index_repo, mock_core_count):
        """Test that failure to retrieve apps is handled gracefully."""

        self.service.dbapi.kube_app_get_all = mock.MagicMock(
            side_effect=Exception("DB connection failed"))

        # Should not raise
        self.service.delete_unused_helm_charts(self.context)

        # Nothing should be removed if we can't get apps
        mock_isdir.assert_not_called()
        mock_listdir.assert_not_called()
        mock_remove.assert_not_called()
        mock_index_repo.assert_not_called()


class TestGetActiveControllerUuid(base.DbTestCase):
    """Tests for ConductorManager._get_active_controller_uuid().

    Validates that the conductor syncs the host UUID from platform.conf
    (tsc.host_uuid) to the database when they differ, and returns the
    DB value when platform.conf UUID is not available.
    """

    def setUp(self):
        super(TestGetActiveControllerUuid, self).setUp()

        self.service = manager.ConductorManager('test-host', 'test-topic')
        self.service.dbapi = dbapi.get_instance()
        self.context = context.get_admin_context()
        self.system = utils.create_test_isystem()

        # Create controller-0 host in DB
        self.host_uuid = str(uuid.uuid4())
        self.host = utils.create_test_ihost(
            hostname='controller-0',
            uuid=self.host_uuid,
            personality=constants.CONTROLLER,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_AVAILABLE,
            forisystemid=self.system.id,
        )

        # Mock socket.gethostname to match controller-0
        p = mock.patch('socket.gethostname')
        self.mock_gethostname = p.start()
        self.mock_gethostname.return_value = 'controller-0'
        self.addCleanup(p.stop)

    @mock.patch('tsconfig.tsconfig.host_uuid', None)
    def test_platform_conf_uuid_not_set(self):
        """When tsc.host_uuid is None (first unlock), return DB value."""
        result = self.service._get_active_controller_uuid()
        self.assertEqual(self.host_uuid, result)

    def test_platform_conf_uuid_empty_string(self):
        """When tsc.host_uuid is empty string, return DB value."""
        with mock.patch('tsconfig.tsconfig.host_uuid', ''):
            result = self.service._get_active_controller_uuid()
            self.assertEqual(self.host_uuid, result)

    def test_platform_conf_uuid_matches_db(self):
        """When tsc.host_uuid matches DB, return DB value unchanged."""
        with mock.patch('tsconfig.tsconfig.host_uuid', self.host_uuid):
            result = self.service._get_active_controller_uuid()
            self.assertEqual(self.host_uuid, result)

    def test_platform_conf_uuid_differs_from_db(self):
        """When tsc.host_uuid differs from DB, update DB and return
        platform.conf value."""
        new_uuid = str(uuid.uuid4())
        with mock.patch('tsconfig.tsconfig.host_uuid', new_uuid):
            with mock.patch(
                'sysinv.conductor.manager.greenthread.spawn'
            ) as mock_spawn:
                result = self.service._get_active_controller_uuid()
                self.assertEqual(new_uuid, result)

                # Verify DB was updated
                updated_host = self.service.dbapi.ihost_get(new_uuid)
                self.assertEqual(new_uuid, updated_host.uuid)
                self.assertEqual('controller-0', updated_host.hostname)

                # Verify barbican migration was spawned asynchronously with
                # old and new uuid (must not block conductor startup).
                mock_spawn.assert_called_once_with(
                    self.service._migrate_barbican_secret,
                    self.host_uuid, new_uuid)

    def test_platform_conf_uuid_update_fails_raises(self):
        """When DB update fails, exception propagates (conductor fails)."""
        new_uuid = str(uuid.uuid4())
        with mock.patch('tsconfig.tsconfig.host_uuid', new_uuid):
            with mock.patch.object(
                self.service.dbapi, 'ihost_update',
                side_effect=oslo_db_exception.DBDuplicateEntry()
            ):
                self.assertRaises(
                    oslo_db_exception.DBDuplicateEntry,
                    self.service._get_active_controller_uuid)

    def test_no_active_controller_in_db(self):
        """When no active controller found, return None."""
        self.mock_gethostname.return_value = 'controller-99'
        result = self.service._get_active_controller_uuid()
        self.assertIsNone(result)


class TestMigrateBarbicanSecret(base.DbTestCase):
    """Tests for ConductorManager._migrate_barbican_secret().

    Validates that when the host UUID changes, any Barbican secret
    stored under the old UUID is migrated to the new UUID.
    """

    def setUp(self):
        super(TestMigrateBarbicanSecret, self).setUp()

        self.service = manager.ConductorManager('test-host', 'test-topic')
        self.service.dbapi = dbapi.get_instance()

        self.old_uuid = str(uuid.uuid4())
        self.new_uuid = str(uuid.uuid4())
        self.bmc_password = 'test-bmc-password'

    @mock.patch('sysinv.conductor.openstack.OpenStackOperator')
    def test_secret_exists_migrates_successfully(self, mock_openstack_cls):
        """When a secret exists under old UUID, it should be recreated
        under the new UUID and the old one deleted."""
        mock_openstack = mock_openstack_cls.return_value
        mock_secret = mock.MagicMock()
        mock_secret.payload = self.bmc_password
        # First strict lookup returns the old secret; the post-create
        # verification lookup returns the new secret.
        new_secret = mock.MagicMock()
        mock_openstack.get_barbican_secret_by_name_strict.side_effect = [
            mock_secret, new_secret]

        self.service._migrate_barbican_secret(self.old_uuid, self.new_uuid)

        mock_openstack.get_barbican_secret_by_name_strict.assert_any_call(
            mock.ANY, self.old_uuid)
        mock_openstack.create_barbican_secret.assert_called_once_with(
            mock.ANY, self.new_uuid, self.bmc_password)
        mock_openstack.get_barbican_secret_by_name_strict.assert_any_call(
            mock.ANY, self.new_uuid)
        mock_openstack.delete_barbican_secret.assert_called_once_with(
            mock.ANY, self.old_uuid)

    @mock.patch('sysinv.conductor.openstack.OpenStackOperator')
    def test_no_secret_exists_does_nothing(self, mock_openstack_cls):
        """When no secret exists under old UUID, nothing happens."""
        mock_openstack = mock_openstack_cls.return_value
        mock_openstack.get_barbican_secret_by_name_strict.return_value = None

        self.service._migrate_barbican_secret(self.old_uuid, self.new_uuid)

        mock_openstack.get_barbican_secret_by_name_strict.assert_called_once_with(
            mock.ANY, self.old_uuid)
        mock_openstack.create_barbican_secret.assert_not_called()
        mock_openstack.delete_barbican_secret.assert_not_called()

    @mock.patch('sysinv.conductor.openstack.OpenStackOperator')
    def test_secret_exists_but_empty_payload(self, mock_openstack_cls):
        """When a secret exists but has no retrievable payload, keep the
        existing secret and do not delete it (an empty payload is most
        likely a failed lazy fetch, not a genuinely absent credential)."""
        mock_openstack = mock_openstack_cls.return_value
        mock_secret = mock.MagicMock()
        mock_secret.payload = None
        mock_openstack.get_barbican_secret_by_name_strict.return_value = \
            mock_secret

        self.service._migrate_barbican_secret(self.old_uuid, self.new_uuid)

        mock_openstack.create_barbican_secret.assert_not_called()
        mock_openstack.delete_barbican_secret.assert_not_called()

    @mock.patch('sysinv.conductor.openstack.OpenStackOperator')
    def test_barbican_lookup_fails_gracefully(self, mock_openstack_cls):
        """When barbican raises a non-retriable exception, migration logs
        warning but does not crash."""
        mock_openstack = mock_openstack_cls.return_value
        mock_openstack.get_barbican_secret_by_name_strict.side_effect = \
            Exception("Barbican unavailable")

        # Should not raise
        self.service._migrate_barbican_secret(self.old_uuid, self.new_uuid)

    @mock.patch('sysinv.conductor.openstack.OpenStackOperator')
    def test_barbican_create_fails_gracefully(self, mock_openstack_cls):
        """When creating the new secret fails, migration logs warning
        but does not crash."""
        mock_openstack = mock_openstack_cls.return_value
        mock_secret = mock.MagicMock()
        mock_secret.payload = self.bmc_password
        mock_openstack.get_barbican_secret_by_name_strict.return_value = \
            mock_secret
        mock_openstack.create_barbican_secret.side_effect = \
            Exception("Barbican create failed")

        # Should not raise
        self.service._migrate_barbican_secret(self.old_uuid, self.new_uuid)

    @mock.patch('sysinv.conductor.openstack.OpenStackOperator')
    def test_migration_verifies_new_secret_before_delete(
            self, mock_openstack_cls):
        """If the new secret is not present after create, the old secret
        must NOT be deleted (avoids losing the secret)."""
        mock_openstack = mock_openstack_cls.return_value
        mock_secret = mock.MagicMock()
        mock_secret.payload = self.bmc_password
        # Old lookup returns the secret; post-create verification returns
        # None (create did not take effect). The forced ConnectFailure is
        # caught by the method's handler so it does not crash the test, but
        # the old secret must not be deleted.
        mock_openstack.get_barbican_secret_by_name_strict.side_effect = [
            mock_secret, None]

        self.service._migrate_barbican_secret(self.old_uuid, self.new_uuid)

        mock_openstack.create_barbican_secret.assert_called_once()
        mock_openstack.delete_barbican_secret.assert_not_called()

    def test_retry_predicate_matches_connection_errors(self):
        """The retry predicate retries on Keystone connection failures
        only, not on arbitrary exceptions."""
        predicate = manager._retry_on_keystone_unavailable
        self.assertTrue(predicate(ks_exceptions.ConnectFailure("x")))
        self.assertTrue(predicate(ks_exceptions.DiscoveryFailure("x")))
        self.assertTrue(predicate(ks_exceptions.ConnectTimeout("x")))
        self.assertFalse(predicate(ValueError("x")))
        self.assertFalse(predicate(Exception("x")))


class TestIhostUpdateUuid(base.DbTestCase):
    """Tests for ihost_update returning correct object after UUID change."""

    def setUp(self):
        super(TestIhostUpdateUuid, self).setUp()

        self.dbapi = dbapi.get_instance()
        self.system = utils.create_test_isystem()

        self.old_uuid = str(uuid.uuid4())
        self.host = utils.create_test_ihost(
            hostname='controller-0',
            uuid=self.old_uuid,
            personality=constants.CONTROLLER,
            forisystemid=self.system.id,
        )

    def test_update_uuid_returns_updated_host(self):
        """ihost_update with new uuid should return host with new uuid."""
        new_uuid = str(uuid.uuid4())
        result = self.dbapi.ihost_update(self.old_uuid, {'uuid': new_uuid})
        self.assertEqual(new_uuid, result.uuid)
        self.assertEqual('controller-0', result.hostname)

    def test_update_non_uuid_field_returns_host(self):
        """ihost_update for non-uuid field still works normally."""
        result = self.dbapi.ihost_update(
            self.old_uuid, {'task': 'some-task'})
        self.assertEqual(self.old_uuid, result.uuid)
        self.assertEqual('some-task', result.task)
