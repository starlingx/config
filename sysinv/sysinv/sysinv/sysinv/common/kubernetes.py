#
# Copyright (c) 2013-2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# All Rights Reserved.
#

""" System Inventory Kubernetes Utilities and helper functions."""

from __future__ import absolute_import
from distutils.version import LooseVersion
from ipaddress import ip_address
from ipaddress import IPv4Address
import json
import os
import re
import requests
import ruamel.yaml as yaml
from ruamel.yaml.compat import StringIO
import shutil
import time
import tsconfig.tsconfig as tsc

from kubernetes import __version__ as K8S_MODULE_VERSION
from kubernetes import config
from kubernetes import client
from kubernetes.client import Configuration
from kubernetes.client.rest import ApiException
from kubernetes.client.models.v1_container_image import V1ContainerImage
from kubernetes.stream import stream
from six.moves import http_client as httplib
from urllib3.exceptions import MaxRetryError

from oslo_log import log as logging
from sysinv.common import exception
from sysinv.common import constants
from sysinv.common.retrying import retry

K8S_MODULE_MAJOR_VERSION = int(K8S_MODULE_VERSION.split('.')[0])

LOG = logging.getLogger(__name__)

# Kubernetes groups
CERT_MANAGER_GROUP = 'cert-manager.io'

# Kubernetes API versions
V1_ALPHA_2 = 'v1alpha2'
CERT_MANAGER_VERSION = 'v1'


# Kubernetes Files
KUBERNETES_ADMIN_CONF = '/etc/kubernetes/admin.conf'
KUBERNETES_ROOTCA_CERT = '/etc/kubernetes/pki/ca.crt'
KUBERNETES_NEW_ROOTCA_CERT = '/etc/kubernetes/pki/ca_new.crt'
KUBERNETES_APISERVER_CERT = '/etc/kubernetes/pki/apiserver.crt'

# Kubernetes clusters
KUBERNETES_CLUSTER_DEFAULT = "kubernetes"

# Kubernetes users
KUBERNETES_ADMIN_USER = "kubernetes-admin"

# Possible states for each supported kubernetes version
KUBE_STATE_AVAILABLE = 'available'
KUBE_STATE_UNAVAILABLE = 'unavailable'
KUBE_STATE_ACTIVE = 'active'
KUBE_STATE_PARTIAL = 'partial'

# Kubernetes namespaces
NAMESPACE_KUBE_SYSTEM = 'kube-system'
NAMESPACE_DEPLOYMENT = 'deployment'

# Kubernetes control plane components
KUBE_APISERVER = 'kube-apiserver'
KUBE_CONTROLLER_MANAGER = 'kube-controller-manager'
KUBE_SCHEDULER = 'kube-scheduler'

# Kubernetes upgrade states
KUBE_UPGRADE_STARTED = 'upgrade-started'
KUBE_UPGRADE_DOWNLOADING_IMAGES = 'downloading-images'
KUBE_UPGRADE_DOWNLOADING_IMAGES_FAILED = 'downloading-images-failed'
KUBE_UPGRADE_DOWNLOADED_IMAGES = 'downloaded-images'
KUBE_PRE_UPDATING_APPS = 'pre-updating-apps'
KUBE_PRE_UPDATING_APPS_FAILED = 'pre-updating-apps-failed'
KUBE_PRE_UPDATED_APPS = 'pre-updated-apps'
KUBE_POST_UPDATING_APPS = 'post-updating-apps'
KUBE_POST_UPDATING_APPS_FAILED = 'post-updating-apps-failed'
KUBE_POST_UPDATED_APPS = 'post-updated-apps'
KUBE_UPGRADING_NETWORKING = 'upgrading-networking'
KUBE_UPGRADING_NETWORKING_FAILED = 'upgrading-networking-failed'
KUBE_UPGRADED_NETWORKING = 'upgraded-networking'
KUBE_UPGRADING_STORAGE = 'upgrading-storage'
KUBE_UPGRADING_STORAGE_FAILED = 'upgrading-storage-failed'
KUBE_UPGRADED_STORAGE = 'upgraded-storage'
KUBE_UPGRADING_FIRST_MASTER = 'upgrading-first-master'
KUBE_UPGRADING_FIRST_MASTER_FAILED = 'upgrading-first-master-failed'
KUBE_UPGRADED_FIRST_MASTER = 'upgraded-first-master'
KUBE_UPGRADING_SECOND_MASTER = 'upgrading-second-master'
KUBE_UPGRADING_SECOND_MASTER_FAILED = 'upgrading-second-master-failed'
KUBE_UPGRADED_SECOND_MASTER = 'upgraded-second-master'
KUBE_UPGRADING_KUBELETS = 'upgrading-kubelets'
KUBE_UPGRADE_COMPLETE = 'upgrade-complete'
KUBE_UPGRADE_ABORTING = 'upgrade-aborting'
KUBE_UPGRADE_ABORTING_FAILED = 'upgrade-aborting-failed'
KUBE_UPGRADE_ABORTED = 'upgrade-aborted'
KUBE_UPGRADE_CORDON = 'cordon-started'
KUBE_UPGRADE_CORDON_COMPLETE = 'cordon-complete'
KUBE_UPGRADE_CORDON_FAILED = 'cordon-failed'
KUBE_UPGRADE_UNCORDON = 'uncordon-started'
KUBE_UPGRADE_UNCORDON_COMPLETE = 'uncordon-complete'
KUBE_UPGRADE_UNCORDON_FAILED = 'uncordon-failed'

# Kubernetes host upgrade statuses
KUBE_HOST_UPGRADING_CONTROL_PLANE = 'upgrading-control-plane'
KUBE_HOST_UPGRADING_CONTROL_PLANE_FAILED = 'upgrading-control-plane-failed'
KUBE_HOST_UPGRADING_KUBELET = 'upgrading-kubelet'
KUBE_HOST_UPGRADING_KUBELET_FAILED = 'upgrading-kubelet-failed'
KUBE_HOST_UPGRADED_KUBELET = 'upgraded-kubelet'

# Kubernetes rootca update states
KUBE_ROOTCA_UPDATE_STARTED = 'update-started'
KUBE_ROOTCA_UPDATE_CERT_UPLOADED = 'update-new-rootca-cert-uploaded'
KUBE_ROOTCA_UPDATE_CERT_GENERATED = 'update-new-rootca-cert-generated'
KUBE_ROOTCA_UPDATING_PODS_TRUSTBOTHCAS = 'updating-pods-trust-both-cas'
KUBE_ROOTCA_UPDATED_PODS_TRUSTBOTHCAS = 'updated-pods-trust-both-cas'
KUBE_ROOTCA_UPDATING_PODS_TRUSTBOTHCAS_FAILED = 'updating-pods-trust-both-cas-failed'
KUBE_ROOTCA_UPDATING_PODS_TRUSTNEWCA = 'updating-pods-trust-new-ca'
KUBE_ROOTCA_UPDATED_PODS_TRUSTNEWCA = 'updated-pods-trust-new-ca'
KUBE_ROOTCA_UPDATING_PODS_TRUSTNEWCA_FAILED = 'updating-pods-trust-new-ca-failed'
KUBE_ROOTCA_UPDATE_COMPLETED = 'update-completed'
KUBE_ROOTCA_UPDATE_ABORTED = 'update-aborted'

# Kubernetes rootca host update states
KUBE_ROOTCA_UPDATING_HOST_TRUSTBOTHCAS = 'updating-host-trust-both-cas'
KUBE_ROOTCA_UPDATED_HOST_TRUSTBOTHCAS = 'updated-host-trust-both-cas'
KUBE_ROOTCA_UPDATING_HOST_TRUSTBOTHCAS_FAILED = 'updating-host-trust-both-cas-failed'
KUBE_ROOTCA_UPDATING_HOST_UPDATECERTS = 'updating-host-update-certs'
KUBE_ROOTCA_UPDATED_HOST_UPDATECERTS = 'updated-host-update-certs'
KUBE_ROOTCA_UPDATING_HOST_UPDATECERTS_FAILED = 'updating-host-update-certs-failed'
KUBE_ROOTCA_UPDATING_HOST_TRUSTNEWCA = 'updating-host-trust-new-ca'
KUBE_ROOTCA_UPDATED_HOST_TRUSTNEWCA = 'updated-host-trust-new-ca'
KUBE_ROOTCA_UPDATING_HOST_TRUSTNEWCA_FAILED = 'updating-host-trust-new-ca-failed'

# Kubeadm and Kubelet initial versions
# This corresponds to the latest K8s version from the previous release
K8S_INITIAL_CMD_VERSION = '1.24.4'

# Kubernetes constants
MANIFEST_APPLY_TIMEOUT = 60 * 15
MANIFEST_APPLY_INTERVAL = 10
POD_START_TIMEOUT = 60 * 2
POD_START_INTERVAL = 10

# retry for urllib3 max retry error
# Function will fail after 200 seconds
# (API_RETRY_ATTEMPT_NUMBER * API_RETRY_INTERVAL)
# See retry decorator for parameters in detail
API_RETRY_ATTEMPT_NUMBER = 20
API_RETRY_INTERVAL = 10 * 1000  # millisecond

# kubernetes control-plane backup path
# (this is used during k8s upgrades)
KUBE_CONTROL_PLANE_BACKUP_PATH = '/opt/backups/k8s-control-plane/'
KUBE_CONTROL_PLANE_STATIC_PODS_BACKUP_PATH = os.path.join(
    KUBE_CONTROL_PLANE_BACKUP_PATH, 'static-pod-manifests')
KUBE_CONTROL_PLANE_ETCD_BACKUP_PATH = os.path.join(
    KUBE_CONTROL_PLANE_BACKUP_PATH, 'etcd')


def k8s_health_check(tries=20, try_sleep=5, timeout=5,
                     healthz_endpoint=constants.APISERVER_READYZ_ENDPOINT):
    """This checks k8s control-plane component health for a specified
    endpoint, and waits for that endpoint to be up and running.
    This checks the endpoint 'tries' times using a API connection
    timeout, and a sleep interval between tries.

    The default healthz_endpoint corresponds to apiserver on the localhost.

    :param tries: Maximum number of retries to check endpoint health.
    :param try_sleep: sleep interval between retries.
    :param timeout: Time which wait on a response before timing
    out (in seconds).
    :param healthz_endpoint: Endpoint url to check the health.

    Return:
    - rc = True, k8s component health check ok.
    - rc = False, k8s component health check failed.
    """
    # pylint: disable-msg=broad-except
    rc = False
    _tries = tries
    kwargs = {"verify": False, "timeout": timeout}

    while _tries:
        try:
            response = requests.get(healthz_endpoint, **kwargs)
            if response.status_code == 200:
                rc = True
                break
        except requests.exceptions.Timeout:
            rc = False
        except requests.exceptions.RequestException as e:
            LOG.error("requests error occurred: %s" % e)
            rc = False
        _tries -= 1
        if _tries:
            time.sleep(try_sleep)
    if not rc:
        LOG.error('k8s control-plane endpoint %s unhealthy' %
                  healthz_endpoint)
        return rc

    LOG.info('k8s control-plane endpoint %s healthy' %
             healthz_endpoint)
    return rc


def test_kubeapi_health(function):
    """Decorator that checks if k8s endpoints are ready before calling the function.

    param: function: The function to be wrapped.

    Returns: The wrapped function that checks the kubeapi health.
    """
    def wrapper(*args, **kwargs):
        LOG.info("Starting k8s health check")
        if k8s_health_check(tries=30, try_sleep=10, timeout=5):
            return function(*args, **kwargs)
        else:
            raise Exception("Kubeapi is not responsive.")
    return wrapper


def get_kube_versions():
    """Provides a list of supported kubernetes versions in
       increasing order."""
    return [
        {'version': 'v1.24.4',
         'upgrade_from': ['v1.23.1'],
         'downgrade_to': [],
         'applied_patches': [],
         'available_patches': [],
         },
        {'version': 'v1.25.3',
         'upgrade_from': ['v1.24.4'],
         'downgrade_to': [],
         'applied_patches': [],
         'available_patches': [],
         },
        {'version': 'v1.26.1',
         'upgrade_from': ['v1.25.3'],
         'downgrade_to': [],
         'applied_patches': [],
         'available_patches': [],
         },
        {'version': 'v1.27.5',
         'upgrade_from': ['v1.26.1'],
         'downgrade_to': [],
         'applied_patches': [],
         'available_patches': [],
         },
        {'version': 'v1.28.4',
         'upgrade_from': ['v1.27.5'],
         'downgrade_to': [],
         'applied_patches': [],
         'available_patches': [],
         },
        {'version': 'v1.29.2',
         'upgrade_from': ['v1.28.4'],
         'downgrade_to': [],
         'applied_patches': [],
         'available_patches': [],
         },
    ]


def get_latest_supported_version():
    """Returns latest supported k8s version for the release """
    latest_version = get_kube_versions()[-1]['version']
    return latest_version


def is_kube_version_supported(kube_version, min_version=None, max_version=None):
    """Check if the k8s version is supported by the application.

    :param kube_version: the running or target k8s version
    :param min_version (optional): minimum k8s version supported by the app
    :param max_version (optional): maximum k8s version supported by the app

    :returns bool: True if k8s version is supported
    """

    kube_version = kube_version.strip().lstrip('v')
    if ((min_version is not None and LooseVersion(kube_version) <
         LooseVersion(min_version.strip().lstrip('v'))) or
            (max_version is not None and LooseVersion(kube_version) >
             LooseVersion(max_version.strip().lstrip('v')))):
        return False
    return True


def get_kube_networking_upgrade_version(kube_upgrade):
    """Determine the version that kubernetes networking
       should be upgraded to."""
    if kube_upgrade.state in [
            KUBE_UPGRADE_STARTED,
            KUBE_UPGRADE_DOWNLOADING_IMAGES,
            KUBE_UPGRADE_DOWNLOADING_IMAGES_FAILED,
            KUBE_UPGRADE_DOWNLOADED_IMAGES]:
        return kube_upgrade.from_version
    else:
        return kube_upgrade.to_version


def get_kube_storage_upgrade_version(kube_upgrade):
    """Determine the version that kubernetes storage
       should be upgraded to."""
    if kube_upgrade.state in [
            KUBE_UPGRADE_STARTED,
            KUBE_UPGRADE_DOWNLOADING_IMAGES,
            KUBE_UPGRADE_DOWNLOADING_IMAGES_FAILED,
            KUBE_UPGRADE_DOWNLOADED_IMAGES]:
        return kube_upgrade.from_version
    else:
        return kube_upgrade.to_version


def is_k8s_configured():
    """Check to see if the k8s admin config file exists."""
    if os.path.isfile(KUBERNETES_ADMIN_CONF):
        return True
    return False


def create_configmap_obj(namespace, name, filename, **kwargs):
    data_section_name = kwargs.pop('data_section_name', 'data')
    metadata = client.V1ObjectMeta(namespace=namespace, name=name, **kwargs)
    try:
        with open(filename, 'r') as file:
            data = file.read()
            return client.V1ConfigMap(
                api_version="v1", kind="ConfigMap",
                metadata=metadata,
                data={data_section_name: data})
    except Exception as e:
        LOG.error("Kubernetes exception in create_configmap_obj: %s" % e)
        raise


def backup_kube_static_pods(backup_path):
    """Backup manifests of control plane static pods i.e. kube-apiserver,
    kube-controller-manager, kube-scheduler to a secured location.

    :param backup_path: secured location to backup static pods
     """
    try:
        shutil.copytree('/etc/kubernetes/manifests/', backup_path)
        LOG.info('Kubernetes static pod manifests copied to: %s' % backup_path)
    except Exception as e:
        LOG.error('Error copying kubernetes static pods manifests: %s' % e)
        raise


# https://github.com/kubernetes-client/python/issues/895
# If a container image contains no tag or digest, patch/list
# node requests sent via python Kubernetes client will be
# returned with exception because python Kubernetes client
# deserializes the ContainerImage response from kube-apiserver
# and it fails the validation due to the empty image name.
#
# Implement this workaround to replace the V1ContainerImage.names
# in the python Kubernetes client to bypass the "none image"
# check because the error is not from kubernetes. If patching
# a node with a new host label, we can see the label is
# created successfully in Kubernetes.
#
# This workaround should be removed if the proposed solutions
# can be made in kubernetes or a workaround can be implemented
# in containerd.
# https://github.com/kubernetes/kubernetes/pull/79018
# https://github.com/containerd/containerd/issues/4771
def names(self, names):
    """Monkey patch V1ContainerImage with this to set the names."""
    self._names = names


# Replacing address of "names" in V1ContainerImage
# with the "names" defined above
V1ContainerImage.names = V1ContainerImage.names.setter(names)


class KubeOperator(object):

    def __init__(self, host=None):
        self.host = host
        self._kube_client_batch = None
        self._kube_client_core = None
        self._kube_client_policy = None
        self._kube_client_custom_objects = None
        self._kube_client_admission_registration = None
        self._kube_client_rbac_authorization = None
        self._kube_client_extensions = None

    def _load_kube_config(self):
        if not is_k8s_configured():
            raise exception.KubeNotConfigured()

        config.load_kube_config(KUBERNETES_ADMIN_CONF)

        # Workaround: Turn off SSL/TLS verification
        if K8S_MODULE_MAJOR_VERSION < 12:
            c = Configuration()
        else:
            c = Configuration().get_default_copy()
        c.verify_ssl = False
        if self.host is not None:
            c.host = self.host
        Configuration.set_default(c)
        return c

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

    def _get_kubernetesclient_policy(self):
        if not self._kube_client_policy:
            self._load_kube_config()
            self._kube_client_policy = client.PolicyV1beta1Api()
        return self._kube_client_policy

    def _get_kubernetesclient_custom_objects(self):
        if not self._kube_client_custom_objects:
            self._load_kube_config()
            self._kube_client_custom_objects = client.CustomObjectsApi()
        return self._kube_client_custom_objects

    def _get_kubernetesclient_admission_registration(self):
        if not self._kube_client_admission_registration:
            self._load_kube_config()
            self._kube_client_admission_registration = client.AdmissionregistrationV1Api()
        return self._kube_client_admission_registration

    def _get_kubernetesclient_rbac_authorization(self):
        if not self._kube_client_rbac_authorization:
            self._load_kube_config()
            self._kube_client_rbac_authorization = client.RbacAuthorizationV1Api()
        return self._kube_client_rbac_authorization

    def _get_kubernetesclient_extensions(self):
        if not self._kube_client_extensions:
            self._load_kube_config()
            self._kube_client_extensions = client.ApiextensionsV1Api()
        return self._kube_client_extensions

    def _retry_on_urllibs3_MaxRetryError(ex):  # pylint: disable=no-self-argument
        if isinstance(ex, MaxRetryError):
            LOG.warn('Retrying against MaxRetryError: {}'.format(ex))
            return True
        else:
            return False

    def _retry_on_urllibs3_RetryError(ex):  # pylint: disable=no-self-argument
        if isinstance(ex, MaxRetryError):
            LOG.warn('Retrying against MaxRetryError: {}'.format(ex))
            return True
        elif isinstance(ex, ValueError):
            LOG.warn('Retrying against ValueError: {}'.format(ex))
            return True
        else:
            return False

    def kube_get_kubernetes_config(self):
        return self._load_kube_config()

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

    @retry(stop_max_attempt_number=API_RETRY_ATTEMPT_NUMBER,
           wait_fixed=API_RETRY_INTERVAL,
           retry_on_exception=_retry_on_urllibs3_MaxRetryError)
    def kube_get_nodes(self):
        try:
            api_response = self._get_kubernetesclient_core().list_node()
            LOG.debug("Response: %s" % api_response)
            return api_response.items
        except Exception as e:
            LOG.warn("Kubernetes exception in kube_get_nodes: %s" % e)
            raise

    @retry(stop_max_attempt_number=API_RETRY_ATTEMPT_NUMBER,
           wait_fixed=API_RETRY_INTERVAL,
           retry_on_exception=_retry_on_urllibs3_MaxRetryError)
    def kube_get_node_status(self, name):
        try:
            api_response = self._get_kubernetesclient_core().read_node_status(name)
            LOG.debug("Response: %s" % api_response)
            return api_response
        except Exception as e:
            LOG.warn("Kubernetes exception in kube_get_node_status: %s" % e)
            raise

    def kube_namespaced_pods_exist(self, namespace):
        LOG.debug("kube_namespaced_pods_exist, namespace=%s" %
                  (namespace))
        try:
            api_response = self._get_kubernetesclient_core().list_namespaced_pod(
                namespace)

            if api_response.items:
                return True
            else:
                return False
        except ApiException as e:
            LOG.error("Kubernetes exception in list_namespaced_pod: %s" % e)
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

    def kube_get_namespace_name_list(self):
        c = self._get_kubernetesclient_core()
        try:
            ns_list = c.list_namespace()
            return list(set(ns.metadata.name for ns in ns_list.items))
        except Exception as e:
            LOG.error("Failed to get Namespace list: %s" % e)
            raise

    def kube_list_secret_for_all_namespaces(self, selector=None):
        c = self._get_kubernetesclient_core()
        try:
            secret_list = c.list_secret_for_all_namespaces(field_selector=selector)
            return secret_list.items
        except ApiException as e:
            if e.status == httplib.NOT_FOUND:
                return None
            else:
                LOG.error("Failed to list secrets in all namespaces %s" % e.body)
                raise
        except Exception as e:
            LOG.exception(e)
            raise

    def kube_list_secret(self, namespace):
        c = self._get_kubernetesclient_core()
        try:
            secret_list = c.list_namespaced_secret(namespace)
            return secret_list.items
        except ApiException as e:
            if e.status == httplib.NOT_FOUND:
                return None
            else:
                LOG.error("Failed to list secret under "
                          "Namespace %s: %s" % (namespace, e.body))
                raise
        except Exception as e:
            LOG.exception(e)
            raise

    @retry(stop_max_attempt_number=API_RETRY_ATTEMPT_NUMBER,
           wait_fixed=API_RETRY_INTERVAL,
           retry_on_exception=_retry_on_urllibs3_MaxRetryError)
    def kube_get_secret(self, name, namespace):
        c = self._get_kubernetesclient_core()
        try:
            return c.read_namespaced_secret(name, namespace, _request_timeout=(30, 30))
        except ApiException as e:
            if e.status == httplib.NOT_FOUND:
                return None
            else:
                LOG.error("Failed to get Secret %s under "
                          "Namespace %s: %s" % (name, namespace, e.body))
                raise
        except Exception as e:
            LOG.warn("Kubernetes exception in kube_get_secret: %s" % e)
            raise

    def kube_patch_namespace(self, namespace, body):
        c = self._get_kubernetesclient_core()
        try:
            c.patch_namespace(namespace, body)
        except Exception as e:
            LOG.error("Failed to patch namespace %s with patch %s: %s"
                      % (namespace, body, e))
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
            body = c.read_namespaced_secret(name, src_namespace)
            body.metadata.resource_version = None
            body.metadata.namespace = dst_namespace
            c.create_namespaced_secret(dst_namespace, body)
        except Exception as e:
            LOG.error("Failed to copy Secret %s from Namespace %s to Namespace "
                      "%s: %s" % (name, src_namespace, dst_namespace, e))
            raise

    def kube_patch_secret(self, name, namespace, body):
        c = self._get_kubernetesclient_core()
        try:
            return c.patch_namespaced_secret(name, namespace, body)
        except Exception as e:
            LOG.error("Failed to patch Secret %s under Namespace %s: "
                      "%s" % (name, namespace, e))
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
            return c.delete_namespaced_secret(name, namespace, body=body)
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
            c.delete_namespace(namespace, body=body)
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

    def kube_read_config_map(self, name, namespace):
        c = self._get_kubernetesclient_core()
        try:
            configmap = c.read_namespaced_config_map(name, namespace)
            return configmap
        except ApiException as e:
            if e.status == httplib.NOT_FOUND:
                LOG.error("Failed to read Configmap")
                return None
            else:
                LOG.error("Failed to get ConfigMap %s under "
                          "Namespace %s: %s" % (name, namespace, e.body))
                raise
        except Exception as e:
            LOG.error("Kubernetes exception in kube_read_config_map: %s" % e)
            raise
        return None

    def kube_patch_config_map(self, name, namespace, body):
        c = self._get_kubernetesclient_core()
        try:
            c.patch_namespaced_config_map(name, namespace, body)
        except Exception as e:
            LOG.error("Failed to patch ConfigMap %s under Namespace %s: "
                      "%s" % (body['metadata']['name'], namespace, e))
            raise

    def kube_create_config_map(self, namespace, body):
        c = self._get_kubernetesclient_core()
        try:
            c.create_namespaced_config_map(namespace, body)
        except Exception as e:
            LOG.error("Failed to create ConfigMap %s under Namespace %s: "
                      "%s" % (body['metadata']['name'], namespace, e))
            raise

    def kube_create_config_map_from_file(self, namespace, name, filename, **kwargs):
        body = create_configmap_obj(namespace, name, filename, **kwargs)

        c = self._get_kubernetesclient_core()
        try:
            c.create_namespaced_config_map(namespace, body)
        except Exception as e:
            LOG.error("Failed to create ConfigMap %s under Namespace %s: "
                      "%s" % (body.metadata['name'], namespace, e))
            raise

    def kube_copy_config_map(self, name, src_namespace, dst_namespace):
        c = self._get_kubernetesclient_core()
        try:
            body = c.read_namespaced_config_map(name, src_namespace)
            body.metadata.resource_version = None
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
            c.delete_namespaced_config_map(name, namespace, body=body)
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

    def list_custom_resources(self, group, version, plural, pretty=False, label_selector="",
                              resource_version="", watch=False):
        custom_resource_api = self._get_kubernetesclient_custom_objects()

        try:
            cr_obj_list = custom_resource_api.list_cluster_custom_object(
                group,
                version,
                plural,
                pretty=pretty,
                label_selector=label_selector,
                resource_version=resource_version,
                watch=watch
            )
        except ApiException as e:
            if e.status == httplib.NOT_FOUND:
                return None
            else:
                LOG.error("Fail to list custom resources:%s. %s"
                          % (plural, e))
                raise
        else:
            return cr_obj_list.get("items")

    def list_namespaced_custom_resources(self, group, version, namespace, plural,
                                         pretty=False, label_selector="",
                                         resource_version="", watch=False):
        custom_resource_api = self._get_kubernetesclient_custom_objects()

        try:
            cr_obj_list = custom_resource_api.list_namespaced_custom_object(
                group,
                version,
                namespace,
                plural,
                pretty=pretty,
                label_selector=label_selector,
                resource_version=resource_version,
                watch=watch
            )
        except ApiException as e:
            if e.status == httplib.NOT_FOUND:
                return None
            else:
                LOG.error("Fail to list namespaced custom resources:%s. %s"
                          % (plural, e))
                raise
        else:
            return cr_obj_list.get("items")

    def get_custom_resource(self, group, version, namespace, plural, name):
        custom_resource_api = self._get_kubernetesclient_custom_objects()

        try:
            cr_obj = custom_resource_api.get_namespaced_custom_object(
                group,
                version,
                namespace,
                plural,
                name)
        except ApiException as e:
            if e.status == httplib.NOT_FOUND:
                return None
            else:
                LOG.error("Fail to access %s:%s. %s" % (namespace, name, e))
                raise
        else:
            return cr_obj

    def apply_custom_resource(self, group, version, namespace, plural, name, body):
        custom_resource_api = self._get_kubernetesclient_custom_objects()

        # if resource already exists we apply just a patch
        cr_obj = self.get_custom_resource(group, version, namespace, plural, name)
        if cr_obj:
            custom_resource_api.patch_namespaced_custom_object(group,
                                                               version,
                                                               namespace,
                                                               plural,
                                                               name,
                                                               body)
        else:
            custom_resource_api.create_namespaced_custom_object(group,
                                                                version,
                                                                namespace,
                                                                plural,
                                                                body)

    def delete_custom_resource(self, group, version, namespace, plural, name):
        c = self._get_kubernetesclient_custom_objects()
        body = {}

        try:
            c.delete_namespaced_custom_object(group, version, namespace,
                plural, name, body=body)
        except ApiException as ex:
            if ex.reason == "Not Found":
                LOG.warn("Failed to delete custom resource object, Namespace "
                         "%s: %s" % (namespace,
                                     str(ex.body).replace('\n', ' ')))
                pass
        except Exception as e:
            LOG.error("Failed to delete custom resource object, Namespace %s: %s"
                      % (namespace, e))
            raise

    def get_transform_patch_custom_resource(self, group, version, namespace,
                                            plural, name, transform, raise_error=True):
        """ Apply a custom resource after it was transformed by a function

        :param group: Used by k8s API to determine resource
        :param version: Used by k8s API to determine resource
        :param namespace: Used by k8s API to determine resource
        :param plural: Used by k8s API to determine resource
        :param name: Used by k8s API to determine resource
        :param transform: A function used to transform the resource
                          For example access the dictionary and change some
                          fields.
        :param raise_error: Control the exception handling here.
                            If True, log an error and raise errors further.
                            If False, log a warning and return from function.

        :return: True if everything finished successfully.
                 False otherwise.
        """
        kind = group + '/' + version
        try:
            custom_resource = self.get_custom_resource(
                group,
                version,
                namespace,
                plural,
                name)
        except Exception as err:
            if raise_error:
                LOG.error("Failed to get resource kind {}, name {}: {}"
                          "".format(kind, name, err))
                raise
            else:
                LOG.warning("Failed to get resource kind {}, name {}: {}"
                            "".format(kind, name, err))
                return False

        try:
            transform(custom_resource)
        except Exception as err:
            if raise_error:
                LOG.error("Failed to transform resource {} using {}: {}"
                          "".format(custom_resource, transform, err))
                raise
            else:
                LOG.warning("Failed to transform resource {} using {}: {}"
                            "".format(custom_resource, transform, err))
                return False

        try:
            self.apply_custom_resource(
                group,
                version,
                namespace,
                plural,
                name,
                custom_resource
            )
        except Exception as err:
            if raise_error:
                LOG.error("Failed to patch kind {}, name {}: {}"
                          "".format(kind, name, err))
                raise
            else:
                LOG.warning("Failed to patch kind {}, name {}: {}"
                            "".format(kind, name, err))
                return False

        return True

    def get_clusterwide_custom_resource(self, group, version, plural, name):
        custom_resource_api = self._get_kubernetesclient_custom_objects()

        try:
            cr_obj = custom_resource_api.get_cluster_custom_object(group,
                                                                   version,
                                                                   plural,
                                                                   name)
        except ApiException as e:
            if e.status == httplib.NOT_FOUND:
                return None
            else:
                LOG.error("Fail to access %s. %s" % (name, e))
                raise
        else:
            return cr_obj

    def apply_clusterwide_custom_resource(self, group, version, plural, name, body):
        custom_resource_api = self._get_kubernetesclient_custom_objects()

        # if resource already exists we apply just a patch
        cr_obj = self.get_clusterwide_custom_resource(group, version, plural, name)
        if cr_obj:
            custom_resource_api.patch_cluster_custom_object(group,
                                                            version,
                                                            plural,
                                                            name,
                                                            body)
        else:
            custom_resource_api.create_cluster_custom_object(group,
                                                             version,
                                                             plural,
                                                             body)

    def delete_clusterwide_custom_resource(self, group, version, plural, name):
        c = self._get_kubernetesclient_custom_objects()
        body = {}

        try:
            c.delete_cluster_custom_object(group, version, plural, name, body=body)
        except ApiException as ex:
            if ex.reason == "Not Found":
                LOG.warn("Failed to delete clusterwide custom resource object. "
                         "Object doesn't exist. %s" % (str(ex.body).replace('\n', ' ')))
                pass
        except Exception as e:
            LOG.error("Failed to delete clusterwide custom resource object, %s" % (e))
            raise

    def kube_get_service_account(self, name, namespace):
        c = self._get_kubernetesclient_core()
        try:
            return c.read_namespaced_service_account(name, namespace)
        except ApiException as e:
            if e.status == httplib.NOT_FOUND:
                return None
            else:
                LOG.error("Failed to get ServiceAccount %s under "
                          "Namespace %s: %s" % (name, namespace, e.body))
                raise
        except Exception as e:
            LOG.error("Kubernetes exception in kube_get_service_account: %s" % e)
            raise

    def kube_get_service_account_token(self, name, namespace):
        sa = self.kube_get_service_account(name, namespace)
        if not sa:
            # ServiceAccount does not exist, no token available
            return None

        secret = self.kube_get_secret(sa.secrets[0].name, namespace)
        return secret.data.get('token')

    @retry(stop_max_attempt_number=API_RETRY_ATTEMPT_NUMBER,
           wait_fixed=API_RETRY_INTERVAL,
           retry_on_exception=_retry_on_urllibs3_MaxRetryError)
    def kube_get_control_plane_pod_ready_status(self):
        """Returns the ready status of the control plane pods."""
        c = self._get_kubernetesclient_core()

        # First get a list of control-plane nodes
        master_nodes = list()
        api_response = c.list_node(
            label_selector="node-role.kubernetes.io/control-plane")
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

    @retry(stop_max_attempt_number=API_RETRY_ATTEMPT_NUMBER,
           wait_fixed=API_RETRY_INTERVAL,
           retry_on_exception=_retry_on_urllibs3_RetryError)
    def kube_get_control_plane_versions(self):
        """Returns the lowest control plane component version on each
        master node."""
        c = self._get_kubernetesclient_core()

        # First get a list of control-plane nodes
        master_nodes = list()
        api_response = c.list_node(
            label_selector="node-role.kubernetes.io/control-plane")
        for node in api_response.items:
            master_nodes.append(node.metadata.name)
        if not master_nodes:
            LOG.error("Error getting control-plane nodes in "
                      "kube_get_control_plane_versions().")
            raise ValueError('Error with kubernetes client list_node().')

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
                else:
                    LOG.error("Error getting image for pod %s in "
                              "kube_get_control_plane_versions()." % pod_name)
                    raise ValueError('Error with kube_get_image_by_pod_name().')

            # Calculate the lowest version
            try:
                node_versions[node_name] = str(min(versions))
            except Exception as e:
                LOG.error("Error getting min k8s version in "
                          "kube_get_control_plane_versions(). %s" % e)
                raise

        return node_versions

    @retry(stop_max_attempt_number=API_RETRY_ATTEMPT_NUMBER,
           wait_fixed=API_RETRY_INTERVAL,
           retry_on_exception=_retry_on_urllibs3_MaxRetryError)
    def kube_get_kubelet_versions(self):
        """Returns the kubelet version on each node."""
        c = self._get_kubernetesclient_core()

        kubelet_versions = dict()

        api_response = c.list_node()
        for node in api_response.items:
            kubelet_versions[node.metadata.name] = \
                node.status.node_info.kubelet_version

        return kubelet_versions

    def kube_get_higher_patch_version(self, current_version, target_version):
        """Returns the list of all k8s "v<major>.<minor>.<patch>"
        versions that are greater than the current_version and up
        to the final target_version, keeping only the highest patch
        version for a given minor version. The list will contain minor
        versions that increment by 1 each time."""

        if LooseVersion(target_version) <= LooseVersion(current_version):
            LOG.error("Target version should be greater than or "
                      "equal to current version")
            return None
        # Get version lists
        kube_versions = get_kube_versions()
        kube_versions = sorted(kube_versions, key=lambda v: LooseVersion(v['version']))
        current_major_minor = ".".join(current_version.split(".")[:2])
        major_minor_version = set()
        final_versions = list()
        intermediate_versions = list()

        # loop over all k8s versions in minor.major.patch version sorted order
        # exclude from the list:
        # -- versions > the current version
        # -- versions <= target_version
        # -- version == current version
        for version in kube_versions:
            major_minor = ".".join(version['version'].split(".")[:2])
            if LooseVersion(version['version']) > LooseVersion(current_version) \
                and LooseVersion(version['version']) <= LooseVersion(target_version) \
                    and current_major_minor not in major_minor:
                intermediate_versions.append(version['version'])
                major_minor_version.add(major_minor)

        # Get Max patch version list of all intermediate versions
        for ver_list in major_minor_version:
            result = [v for v in intermediate_versions if ver_list in v]
            final_versions.append(max(result, key=lambda x: LooseVersion(x)))

        final_versions = sorted(final_versions, key=lambda v: LooseVersion(v))

        return final_versions

    def kube_get_lower_equal_versions(self, target_version):
        """This function returns list with versions
           less than or equal to the target_version"""
        kube_versions = get_kube_versions()
        version_list = []
        for version in kube_versions:
            if LooseVersion(version['version']) <= LooseVersion(target_version):
                version_list.append(version['version'])
        return version_list

    def kube_get_version_states(self):
        """Returns the state of each known kubernetes version."""

        # Set counts to 0
        version_counts = dict()
        kube_versions = get_kube_versions()
        for version in kube_versions:
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
                version_states[version] = KUBE_STATE_UNAVAILABLE

        # If only a single version is running, then mark it as active
        if len(active_candidates) == 1:
            active_version = active_candidates[0]
            version_states[active_version] = KUBE_STATE_ACTIVE

            # mark the versions who can upgrade_from the active one as available
            for version in kube_versions:
                if active_version in version['upgrade_from']:
                    version_states[version['version']] = KUBE_STATE_AVAILABLE
                if (tsc.system_mode == constants.SYSTEM_MODE_SIMPLEX) and \
                        LooseVersion(version['version']) > LooseVersion(active_version):
                    version_states[version['version']] = KUBE_STATE_AVAILABLE

        return version_states

    @retry(stop_max_attempt_number=API_RETRY_ATTEMPT_NUMBER,
           wait_fixed=API_RETRY_INTERVAL,
           retry_on_exception=_retry_on_urllibs3_MaxRetryError)
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

    def kube_get_all_pods(self):
        c = self._get_kubernetesclient_core()
        try:
            api_response = c.list_pod_for_all_namespaces(watch=False)
            return api_response.items
        except Exception as e:
            LOG.error("Kubernetes exception in "
                      "kube_get_pods: %s" % e)
            raise

    def kube_delete_pod(self, name, namespace, **kwargs):
        body = {}

        if kwargs:
            body.update(kwargs)

        c = self._get_kubernetesclient_core()
        try:
            api_response = c.delete_namespaced_pod(name, namespace, body=body)
            LOG.debug("%s" % api_response)
            return True
        except ApiException as e:
            if e.status == httplib.NOT_FOUND:
                LOG.warn("Pod %s/%s not found." % (namespace, name))
                return False
            else:
                LOG.error("Failed to delete Pod %s/%s: "
                          "%s" % (namespace, name, e.body))
                raise
        except Exception as e:
            LOG.error("Kubernetes exception in kube_delete_pod: %s" % e)
            raise

    def kube_get_pod(self, name, namespace):
        c = self._get_kubernetesclient_core()
        try:
            api_response = c.read_namespaced_pod(name, namespace)
            return api_response
        except ApiException as e:
            if e.status == httplib.NOT_FOUND:
                return None
            else:
                LOG.error("Failed to get Pod %s/%s: %s" % (namespace, name,
                                                           e.body))
                raise
        except Exception as e:
            LOG.error("Kubernetes exception in "
                      "kube_get_pod %s/%s: %s" % (namespace, name, e))

    @retry(stop_max_attempt_number=API_RETRY_ATTEMPT_NUMBER,
           wait_fixed=API_RETRY_INTERVAL,
           retry_on_exception=_retry_on_urllibs3_MaxRetryError)
    def kube_get_pods_by_selector(self, namespace, label_selector,
                                  field_selector):
        c = self._get_kubernetesclient_core()
        try:
            api_response = c.list_namespaced_pod(namespace,
                label_selector="%s" % label_selector,
                field_selector="%s" % field_selector)
            LOG.debug("Response: %s" % api_response)
            return api_response.items
        except ApiException as e:
            LOG.warn("Kubernetes exception in "
                     "kube_get_pods_by_selector %s/%s/%s: %s",
                     namespace, label_selector, field_selector, e)
            raise

    # NOTE: This is desired method to exec commands in a container.
    # The minimal usage example indicates this can get separate streams for
    # stdout and stderr. The code below produces a string of merged output,
    # so we cannot deduce whether the provided exec_command is failing.
    # This API can replace Popen/poll/kubectl exec calls if we peek at
    # api_response. We require ability to poll, read and flush output from
    # long running commands, wait for command completion, and timeout.
    # See the following documentation:
    # https://github.com/kubernetes-client/python/blob/master/examples/pod_exec.py
    # https://github.com/kubernetes-client/python/blob/master/kubernetes/docs/CoreV1Api.md
    def kube_exec_container_stream(self, name, namespace, exec_command, container=None):
        c = self._get_kubernetesclient_core()
        try:
            api_response = stream(c.connect_get_namespaced_pod_exec,
                name,
                namespace,
                container=container,
                command=exec_command,
                stderr=True, stdin=False,
                stdout=True, tty=False)
            return api_response
        except ApiException as e:
            LOG.error("Failed to exec Pod %s/%s: %s" % (namespace, name,
                                                        e.body))
            raise
        except Exception as e:
            LOG.error("Kubernetes exception in "
                      "kube_exec_container %s/%s: %s" % (namespace, name, e))
            raise

    def kube_delete_validating_webhook_configuration(self, name, **kwargs):
        c = self._get_kubernetesclient_admission_registration()
        body = {}

        if kwargs:
            body.update(kwargs)

        try:
            c.delete_validating_webhook_configuration(name, body=body)
        except ApiException as e:
            if e.status == httplib.NOT_FOUND:
                LOG.warn("ValidatingWebhookConfiguration %s "
                         "not found." % name)
            else:
                LOG.error("Failed to clean up ValidatingWebhookConfiguration "
                          "%s : %s" % (name, e.body))
                raise
        except Exception as e:
            LOG.error("Kubernetes exception "
                      "in kube_delete_validating_webhook_configuration: %s" % e)
            raise

    def kube_get_validating_webhook_configurations_by_selector(self, label_selector, field_selector):
        c = self._get_kubernetesclient_admission_registration()
        try:
            api_response = c.list_validating_webhook_configuration(
                label_selector="%s" % label_selector,
                field_selector="%s" % field_selector)
            LOG.debug("kube_get_validating_webhook_configurations_by_selector "
                      "Response: %s" % api_response)
            return api_response.items
        except ApiException as e:
            LOG.error("Kubernetes exception in "
                      "kube_get_validating_webhook_configurations_by_selector %s/%s: %s",
                       label_selector, field_selector, e)
            raise

    def kube_delete_mutating_webhook_configuration(self, name, **kwargs):
        c = self._get_kubernetesclient_admission_registration()
        body = {}

        if kwargs:
            body.update(kwargs)

        try:
            c.delete_mutating_webhook_configuration(name, body=body)
        except ApiException as e:
            if e.status == httplib.NOT_FOUND:
                LOG.warn("MutatingWebhookConfiguration %s "
                         "not found." % name)
            else:
                LOG.error("Failed to clean up MutatingWebhookConfiguration "
                          "%s : %s" % (name, e.body))
                raise
        except Exception as e:
            LOG.error("Kubernetes exception "
                      "in kube_delete_mutating_webhook_configuration: %s" % e)
            raise

    def kube_get_mutating_webhook_configurations_by_selector(self, label_selector, field_selector):
        c = self._get_kubernetesclient_admission_registration()
        try:
            api_response = c.list_mutating_webhook_configuration(
                label_selector="%s" % label_selector,
                field_selector="%s" % field_selector)
            LOG.debug("kube_get_mutating_webhook_configurations_by_selector "
                      "Response: %s" % api_response)
            return api_response.items
        except ApiException as e:
            LOG.error("Kubernetes exception in "
                      "kube_get_mutating_webhook_configurations_by_selector %s/%s: %s",
                       label_selector, field_selector, e)
            raise

    def get_cert_secret(self, name, namespace, max_retries=60):
        for _ in range(max_retries):
            secret = self.kube_get_secret(name, namespace)
            if secret is not None and secret.data.get("tls.crt"):
                LOG.debug("secret = %s" % secret)
                return secret
            time.sleep(1)
        return None

    def kubeadm_configmap_reformat(self, target_version):
        """
        There is an upstream issue in Kubeadm (affecting at least up till 1.24.4)
        where if the "certSANs" field of the kubeadm configmap contains unquoted
        IPv6 addresses in "flow style" it will choke while parsing.  The problematic
        formatting looks like this:

        ClusterConfiguration: |
            apiServer:
                certSANs: [::1, 192.168.206.1, 127.0.0.1, 10.20.7.3]

        While this is fine:

          ClusterConfiguration: |
            apiServer:
                certSANs:
                - ::1
                - 192.168.206.1
                - 127.0.0.1
                - 10.20.7.3
        """
        try:
            configmap_name = 'kubeadm-config'
            configmap = self.kube_read_config_map(configmap_name, 'kube-system')
            newyaml = yaml.YAML()
            stream = StringIO(configmap.data['ClusterConfiguration'])
            info = newyaml.load(stream)
            flow_style = info['apiServer']['certSANs'].fa.flow_style()
            if flow_style:
                # It's using flow syle, so we need to check if any addresses are IPv6.
                need_reformat = False
                try:
                    for addr in info['apiServer']['certSANs']:
                        if type(ip_address(addr)) is not IPv4Address:
                            need_reformat = True
                            break
                except ValueError:
                    # Shouldn't happen if addresses are well-formed.
                    # If it does then reformat to be safe.
                    need_reformat = True

                if need_reformat:
                    LOG.info('Converting kubeadm configmap certSANs to block style.')
                    info['apiServer']['certSANs'].fa.set_block_style()
                    outstream = StringIO()
                    newyaml.dump(info, outstream)
                    configmap = {'data': {'ClusterConfiguration': outstream.getvalue()}}
                    self.kube_patch_config_map(configmap_name, 'kube-system', configmap)
                    LOG.info('Successfully reformatted kubeadm configmap.')
        except Exception as e:
            LOG.exception("Unable to patch kubeadm config_map: %s" % e)
            return 1

        return 0

    def get_psp_resource(self):
        try:
            # Create an API client
            c = self._get_kubernetesclient_policy()

            # Retrieve the resource items
            api_response = c.list_pod_security_policy()
            LOG.debug("Response: %s" % api_response)
            items = api_response.items

            # Return the items if present, or False if not found
            return items if items else False
        except Exception as e:
            LOG.exception("Failed to fetch PodSecurityPolicies: %s" % e)
            raise

    def kube_read_clusterrolebinding(self, name):
        """read a clusterrolebinding with data

        """
        try:
            rbac_authorization = self._get_kubernetesclient_rbac_authorization()
            v1_cluster_role_binding_object = rbac_authorization.read_cluster_role_binding(name)
            LOG.info("Clusterrolebinding %s retrieved successfully." % name)
            return v1_cluster_role_binding_object
        except Exception as ex:
            LOG.exception("Failed to read clusterolebinding %s : %s" % (name, ex))
            raise

    def kube_patch_clusterrolebinding(self, name, body):
        """patch a clusterrolebinding with data

        """
        try:
            rbac_authorization = self._get_kubernetesclient_rbac_authorization()
            v1_cluster_role_binding_object = \
                    rbac_authorization.patch_cluster_role_binding(name, body)
            LOG.info("Clusterrolebinding %s updated successfully. "
                     "Updated object: %s" % (name, v1_cluster_role_binding_object))
        except Exception as ex:
            LOG.exception("Failed to patch clusterolebinding %s : %s" % (name, ex))
            raise
