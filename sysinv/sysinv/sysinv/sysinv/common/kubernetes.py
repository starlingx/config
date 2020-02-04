#
# Copyright (c) 2013-2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
#

""" System Inventory Kubernetes Utilities and helper functions."""

from __future__ import absolute_import
from distutils.version import LooseVersion
import json
import re

from kubernetes import config
from kubernetes import client
from kubernetes.client import Configuration
from kubernetes.client.rest import ApiException
from six.moves import http_client as httplib

from oslo_log import log as logging
from sysinv.common import exception

LOG = logging.getLogger(__name__)

# Possible states for each supported kubernetes version
KUBE_STATE_AVAILABLE = 'available'
KUBE_STATE_ACTIVE = 'active'
KUBE_STATE_PARTIAL = 'partial'

# Kubernetes namespaces
NAMESPACE_KUBE_SYSTEM = 'kube-system'

# Kubernetes control plane components
KUBE_APISERVER = 'kube-apiserver'
KUBE_CONTROLLER_MANAGER = 'kube-controller-manager'
KUBE_SCHEDULER = 'kube-scheduler'

# Kubernetes upgrade states
KUBE_UPGRADE_STARTED = 'upgrade-started'
KUBE_UPGRADE_DOWNLOADING_IMAGES = 'downloading-images'
KUBE_UPGRADE_DOWNLOADING_IMAGES_FAILED = 'downloading-images-failed'
KUBE_UPGRADE_DOWNLOADED_IMAGES = 'downloaded-images'
KUBE_UPGRADING_FIRST_MASTER = 'upgrading-first-master'
KUBE_UPGRADING_FIRST_MASTER_FAILED = 'upgrading-first-master-failed'
KUBE_UPGRADED_FIRST_MASTER = 'upgraded-first-master'
KUBE_UPGRADING_NETWORKING = 'upgrading-networking'
KUBE_UPGRADING_NETWORKING_FAILED = 'upgrading-networking-failed'
KUBE_UPGRADED_NETWORKING = 'upgraded-networking'
KUBE_UPGRADING_SECOND_MASTER = 'upgrading-second-master'
KUBE_UPGRADING_SECOND_MASTER_FAILED = 'upgrading-second-master-failed'
KUBE_UPGRADED_SECOND_MASTER = 'upgraded-second-master'
KUBE_UPGRADING_KUBELETS = 'upgrading-kubelets'
KUBE_UPGRADE_COMPLETE = 'upgrade-complete'

# Kubernetes host upgrade statuses
KUBE_HOST_UPGRADING_CONTROL_PLANE = 'upgrading-control-plane'
KUBE_HOST_UPGRADING_CONTROL_PLANE_FAILED = 'upgrading-control-plane-failed'
KUBE_HOST_UPGRADING_KUBELET = 'upgrading-kubelet'
KUBE_HOST_UPGRADING_KUBELET_FAILED = 'upgrading-kubelet-failed'

# Kubernetes constants
MANIFEST_APPLY_TIMEOUT = 60 * 15
MANIFEST_APPLY_INTERVAL = 10
POD_START_TIMEOUT = 60
POD_START_INTERVAL = 10


def get_kube_versions():
    """Provides a list of supported kubernetes versions."""
    return [
        {'version': 'v1.16.2',
         'upgrade_from': [],
         'downgrade_to': [],
         'applied_patches': [],
         'available_patches': [],
         },
    ]


def get_kube_networking_upgrade_version(kube_upgrade):
    """Determine the version that kubernetes networking
       should be upgraded to."""
    if kube_upgrade.state in [
            KUBE_UPGRADE_STARTED,
            KUBE_UPGRADE_DOWNLOADING_IMAGES,
            KUBE_UPGRADE_DOWNLOADING_IMAGES_FAILED,
            KUBE_UPGRADE_DOWNLOADED_IMAGES,
            KUBE_UPGRADING_FIRST_MASTER,
            KUBE_UPGRADING_FIRST_MASTER_FAILED,
            KUBE_UPGRADED_FIRST_MASTER]:
        return kube_upgrade.from_version
    else:
        return kube_upgrade.to_version


class KubeOperator(object):

    def __init__(self):
        self._kube_client_batch = None
        self._kube_client_core = None
        self._kube_client_custom_objects = None

    def _load_kube_config(self):
        config.load_kube_config('/etc/kubernetes/admin.conf')

        # Workaround: Turn off SSL/TLS verification
        c = Configuration()
        c.verify_ssl = False
        Configuration.set_default(c)

    def _get_kubernetesclient_batch(self):
        if not self._kube_client_batch:
            self._load_kube_config()
            self._kube_client_batch = client.BatchV1Api()
        return self._kube_client_batch

    def _get_kubernetesclient_core(self):
        if not self._kube_client_core:
            self._load_kube_config()
            self._kube_client_core = client.CoreV1Api()
        return self._kube_client_core

    def _get_kubernetesclient_custom_objects(self):
        if not self._kube_client_custom_objects:
            self._load_kube_config()
            self._kube_client_custom_objects = client.CustomObjectsApi()
        return self._kube_client_custom_objects

    def kube_patch_node(self, name, body):
        try:
            api_response = self._get_kubernetesclient_core().patch_node(name, body)
            LOG.debug("Response: %s" % api_response)
        except ApiException as e:
            if e.status == httplib.UNPROCESSABLE_ENTITY:
                reason = json.loads(e.body).get('message', "")
                raise exception.HostLabelInvalid(reason=reason)
            elif e.status == httplib.NOT_FOUND:
                raise exception.KubeNodeNotFound(name=name)
            else:
                raise
        except Exception as e:
            LOG.error("Kubernetes exception in kube_patch_node: %s" % e)
            raise

    def kube_get_nodes(self):
        try:
            api_response = self._get_kubernetesclient_core().list_node()
            LOG.debug("Response: %s" % api_response)
            return api_response.items
        except Exception as e:
            LOG.error("Kubernetes exception in kube_get_nodes: %s" % e)
            raise

    def kube_get_image_by_selector(self, template_name, namespace, container_name):
        LOG.debug("kube_get_image_by_selector template_name=%s, namespace=%s" %
                  (template_name, namespace))
        try:
            # Retrieve the named pod.
            api_response = self._get_kubernetesclient_core().list_namespaced_pod(
                namespace, label_selector="name=%s" % template_name)
            for pod in api_response.items:
                if template_name in pod.metadata.name:
                    for container in pod.spec.containers:
                        if container.name == container_name:
                            return container.image
            return None
        except ApiException as e:
            LOG.error("Kubernetes exception in list_namespaced_pod: %s" % e)
            raise

    def kube_get_image_by_pod_name(self, pod_name, namespace, container_name):
        """Returns the image for the specified container."""
        LOG.debug("kube_get_image_by_pod_name pod_name=%s, namespace=%s, "
                  "container_name=%s" % (pod_name, namespace, container_name))
        try:
            # Retrieve the named pod
            api_response = \
                self._get_kubernetesclient_core().list_namespaced_pod(
                    namespace, field_selector="metadata.name=%s" % pod_name)
            # We expect only one pod with this name
            if len(api_response.items) != 1:
                LOG.warn("Expected one pod with pod_name=%s, namespace=%s, "
                         "container_name=%s but found %d" %
                         (pod_name, namespace, container_name,
                          len(api_response.items)))
            # Use the first pod
            if len(api_response.items) >= 1:
                pod = api_response.items[0]
                for container in pod.spec.containers:
                    if container.name == container_name:
                        return container.image

            return None
        except ApiException as e:
            LOG.error("Kubernetes exception in list_namespaced_pod: %s" % e)
            raise

    def kube_create_namespace(self, namespace):
        body = {'metadata': {'name': namespace}}

        c = self._get_kubernetesclient_core()
        try:
            c.create_namespace(body)
        except ApiException as e:
            if e.status == httplib.CONFLICT:
                # Already exist
                LOG.warn("Namespace %s already exist." % namespace)
            else:
                LOG.error("Failed to create Namespace %s: %s" % (namespace, e.body))
                raise
        except Exception as e:
            LOG.error("Kubernetes exception in "
                      "_kube_create_namespace %s: %s" % (namespace, e))
            raise

    def kube_get_namespace(self, namespace):
        c = self._get_kubernetesclient_core()
        try:
            c.read_namespace(namespace)
            return True
        except ApiException as e:
            if e.status == httplib.NOT_FOUND:
                return False
            else:
                LOG.error("Failed to get Namespace %s: %s" % (namespace, e.body))
                raise
        except Exception as e:
            LOG.error("Kubernetes exception in "
                      "kube_get_namespace %s: %s" % (namespace, e))
            raise

    def kube_get_secret(self, name, namespace):
        c = self._get_kubernetesclient_core()
        try:
            c.read_namespaced_secret(name, namespace)
            return True
        except ApiException as e:
            if e.status == httplib.NOT_FOUND:
                return False
            else:
                LOG.error("Failed to get Secret %s under "
                          "Namespace %s: %s" % (name, namespace, e.body))
                raise
        except Exception as e:
            LOG.error("Kubernetes exception in kube_get_secret: %s" % e)
            raise

    def kube_create_secret(self, namespace, body):
        c = self._get_kubernetesclient_core()
        try:
            c.create_namespaced_secret(namespace, body)
        except Exception as e:
            LOG.error("Failed to create Secret %s under Namespace %s: "
                      "%s" % (body['metadata']['name'], namespace, e))
            raise

    def kube_copy_secret(self, name, src_namespace, dst_namespace):
        c = self._get_kubernetesclient_core()
        try:
            body = c.read_namespaced_secret(name, src_namespace, export=True)
            body.metadata.namespace = dst_namespace
            c.create_namespaced_secret(dst_namespace, body)
        except Exception as e:
            LOG.error("Failed to copy Secret %s from Namespace %s to Namespace "
                      "%s: %s" % (name, src_namespace, dst_namespace, e))
            raise

    def kube_delete_persistent_volume_claim(self, namespace, **kwargs):
        c = self._get_kubernetesclient_core()
        try:
            c.delete_collection_namespaced_persistent_volume_claim(
                namespace, **kwargs)
        except Exception as e:
            LOG.error("Failed to delete Persistent Volume Claim "
                      "under Namespace %s: %s" % (namespace, e))
            raise

    def kube_delete_secret(self, name, namespace, **kwargs):
        body = {}

        if kwargs:
            body.update(kwargs)

        c = self._get_kubernetesclient_core()
        try:
            c.delete_namespaced_secret(name, namespace, body)
        except ApiException as e:
            if e.status == httplib.NOT_FOUND:
                LOG.warn("Secret %s under Namespace %s "
                         "not found." % (name, namespace))
            else:
                LOG.error("Failed to clean up Secret %s under "
                          "Namespace %s: %s" % (name, namespace, e.body))
                raise
        except Exception as e:
            LOG.error("Kubernetes exception in kube_delete_secret: %s" % e)
            raise

    def kube_delete_namespace(self, namespace, **kwargs):
        body = {}

        if kwargs:
            body.update(kwargs)

        c = self._get_kubernetesclient_core()
        try:
            c.delete_namespace(namespace, body)
        except ApiException as e:
            if e.status == httplib.NOT_FOUND:
                LOG.warn("Namespace %s not found." % namespace)
            else:
                LOG.error("Failed to clean up Namespace %s: "
                          "%s" % (namespace, e.body))
                raise
        except Exception as e:
            LOG.error("Kubernetes exception in kube_delete_namespace: %s" % e)
            raise

    def kube_get_config_map(self, name, namespace):
        c = self._get_kubernetesclient_core()
        try:
            c.read_namespaced_config_map(name, namespace)
            return True
        except ApiException as e:
            if e.status == httplib.NOT_FOUND:
                return False
            else:
                LOG.error("Failed to get ConfigMap %s under "
                          "Namespace %s: %s" % (name, namespace, e.body))
                raise
        except Exception as e:
            LOG.error("Kubernetes exception in kube_get_config_map: %s" % e)
            raise

    def kube_create_config_map(self, namespace, body):
        c = self._get_kubernetesclient_core()
        try:
            c.create_namespaced_config_map(namespace, body)
        except Exception as e:
            LOG.error("Failed to create ConfigMap %s under Namespace %s: "
                      "%s" % (body['metadata']['name'], namespace, e))
            raise

    def kube_copy_config_map(self, name, src_namespace, dst_namespace):
        c = self._get_kubernetesclient_core()
        try:
            body = c.read_namespaced_config_map(name, src_namespace, export=True)
            body.metadata.namespace = dst_namespace
            c.create_namespaced_config_map(dst_namespace, body)
        except Exception as e:
            LOG.error("Failed to copy ConfigMap %s from Namespace %s to Namespace "
                      "%s: %s" % (name, src_namespace, dst_namespace, e))
            raise

    def kube_delete_config_map(self, name, namespace, **kwargs):
        body = {}

        if kwargs:
            body.update(kwargs)

        c = self._get_kubernetesclient_core()
        try:
            c.delete_namespaced_config_map(name, namespace, body)
        except ApiException as e:
            if e.status == httplib.NOT_FOUND:
                LOG.warn("ConfigMap %s under Namespace %s "
                         "not found." % (name, namespace))
            else:
                LOG.error("Failed to clean up ConfigMap %s under "
                          "Namespace %s: %s" % (name, namespace, e.body))
                raise
        except Exception as e:
            LOG.error("Kubernetes exception in kube_delete_config_map: %s" % e)
            raise

    def kube_delete_collection_namespaced_job(self, namespace, label):
        c = self._get_kubernetesclient_batch()

        try:
            c.delete_collection_namespaced_job(namespace, label_selector=label)
        except Exception as e:
            LOG.error("Failed to delete Jobs with label %s under "
                      "Namespace %s: %s" % (label, namespace, e))
            raise

    def delete_custom_resource(self, group, version, namespace, plural, name):
        c = self._get_kubernetesclient_custom_objects()
        body = {}

        try:
            c.delete_namespaced_custom_object(group, version, namespace,
                plural, name, body)
        except ApiException as ex:
            if ex.reason == "Not Found":
                pass
        except Exception as e:
            LOG.error("Failed to delete custom object, Namespace %s: %s"
                      % (namespace, e))
            raise

    def kube_get_control_plane_pod_ready_status(self):
        """Returns the ready status of the control plane pods."""
        c = self._get_kubernetesclient_core()

        # First get a list of master nodes
        master_nodes = list()
        api_response = c.list_node(
            label_selector="node-role.kubernetes.io/master")
        for node in api_response.items:
            master_nodes.append(node.metadata.name)

        # Populate status dictionary
        ready_status = dict()
        for node_name in master_nodes:
            for component in [KUBE_APISERVER,
                              KUBE_CONTROLLER_MANAGER,
                              KUBE_SCHEDULER]:
                # Control plane pods are named by component and node.
                # E.g. kube-apiserver-controller-0
                pod_name = component + '-' + node_name
                ready_status[pod_name] = None

        # Retrieve the control plane pods
        api_response = c.list_pod_for_all_namespaces(
            label_selector="component in (%s,%s,%s)" % (
                KUBE_APISERVER, KUBE_CONTROLLER_MANAGER, KUBE_SCHEDULER)
        )
        pods = api_response.items
        for pod in pods:
            if pod.status.conditions is not None:
                for condition in pod.status.conditions:
                    if condition.type == "Ready":
                        ready_status[pod.metadata.name] = condition.status

        return ready_status

    def kube_get_control_plane_versions(self):
        """Returns the lowest control plane component version on each
        master node."""
        c = self._get_kubernetesclient_core()

        # First get a list of master nodes
        master_nodes = list()
        api_response = c.list_node(
            label_selector="node-role.kubernetes.io/master")
        for node in api_response.items:
            master_nodes.append(node.metadata.name)

        node_versions = dict()
        for node_name in master_nodes:
            versions = list()
            for component in [KUBE_APISERVER,
                              KUBE_CONTROLLER_MANAGER,
                              KUBE_SCHEDULER]:
                # Control plane pods are named by component and node.
                # E.g. kube-apiserver-controller-0
                pod_name = component + '-' + node_name
                image = self.kube_get_image_by_pod_name(
                    pod_name, NAMESPACE_KUBE_SYSTEM, component)
                if image is not None:
                    versions.append(LooseVersion(image.rsplit(':')[-1]))

            # Calculate the lowest version
            node_versions[node_name] = str(min(versions))

        return node_versions

    def kube_get_kubelet_versions(self):
        """Returns the kubelet version on each node."""
        c = self._get_kubernetesclient_core()

        kubelet_versions = dict()

        api_response = c.list_node()
        for node in api_response.items:
            kubelet_versions[node.metadata.name] = \
                node.status.node_info.kubelet_version

        return kubelet_versions

    def kube_get_version_states(self):
        """Returns the state of each known kubernetes version."""

        # Set counts to 0
        version_counts = dict()
        for version in get_kube_versions():
            version_counts[version['version']] = 0

        # Count versions running on control plane
        cp_versions = self.kube_get_control_plane_versions()
        for cp_version in cp_versions.values():
            if cp_version in version_counts:
                version_counts[cp_version] += 1
            else:
                LOG.error("Unknown control plane version %s running." %
                          cp_version)

        # Count versions running on kubelets
        kubelet_versions = self.kube_get_kubelet_versions()
        for kubelet_version in kubelet_versions.values():
            if kubelet_version in version_counts:
                version_counts[kubelet_version] += 1
            else:
                LOG.error("Unknown kubelet version %s running." %
                          kubelet_version)

        version_states = dict()
        active_candidates = list()
        for version, count in version_counts.items():
            if count > 0:
                # This version is at least partially running
                version_states[version] = KUBE_STATE_PARTIAL
                active_candidates.append(version)
            else:
                # This version is not running anywhere
                version_states[version] = KUBE_STATE_AVAILABLE

        # If only a single version is running, then mark it as active
        if len(active_candidates) == 1:
            version_states[active_candidates[0]] = KUBE_STATE_ACTIVE

        return version_states

    def kube_get_kubernetes_version(self):
        """Returns the kubernetes version from the kubadm config map."""

        c = self._get_kubernetesclient_core()

        # Get the kubernetes version from the kubeadm config map
        config_map = c.read_namespaced_config_map('kubeadm-config',
                                                  NAMESPACE_KUBE_SYSTEM)
        cluster_config = config_map.data['ClusterConfiguration']
        match = re.search('\nkubernetesVersion: (.*)\n', cluster_config)
        if match is None:
            LOG.error("Unable to find kubernetesVersion in kubeadm-config %s" %
                      config_map)
            return None
        else:
            return match.group(1)
