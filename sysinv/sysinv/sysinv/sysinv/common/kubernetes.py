#
# Copyright (c) 2013-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
#

""" System Inventory Kubernetes Utilities and helper functions."""

from __future__ import absolute_import
import json

from kubernetes import config
from kubernetes import client
from kubernetes.client import Configuration
from kubernetes.client.rest import ApiException
from six.moves import http_client as httplib
from sysinv.common import exception
from sysinv.openstack.common import log as logging

LOG = logging.getLogger(__name__)


class KubeOperator(object):

    def __init__(self, dbapi):
        self._dbapi = dbapi
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
                raise exception.K8sNodeNotFound(name=name)
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

    def kube_get_secret(self, name, namespace):
        c = self._get_kubernetesclient_core()
        try:
            return c.read_namespaced_secret(name, namespace)
        except ApiException as e:
            if e.status == httplib.NOT_FOUND:
                return None
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

    def kube_patch_secret(self, name, namespace, body):
        c = self._get_kubernetesclient_core()
        try:
            c.patch_namespaced_secret(name, namespace, body)
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
