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
        self._kube_client = None

    def _get_kubernetesclient(self):
        if not self._kube_client:
            config.load_kube_config('/etc/kubernetes/admin.conf')

            # Workaround: Turn off SSL/TLS verification
            c = Configuration()
            c.verify_ssl = False
            Configuration.set_default(c)

            self._kube_client = client.CoreV1Api()
        return self._kube_client

    def kube_patch_node(self, name, body):
        try:
            api_response = self._get_kubernetesclient().patch_node(name, body)
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
            api_response = self._get_kubernetesclient().list_node()
            LOG.debug("Response: %s" % api_response)
            return api_response.items
        except Exception as e:
            LOG.error("Kubernetes exception in kube_get_nodes: %s" % e)
            raise

    def kube_create_namespace(self, namespace):
        body = {'metadata': {'name': namespace}}

        c = self._get_kubernetesclient()
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
        c = self._get_kubernetesclient()
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
        c = self._get_kubernetesclient()
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
        c = self._get_kubernetesclient()
        try:
            c.create_namespaced_secret(namespace, body)
        except Exception as e:
            LOG.error("Failed to create Secret %s under Namespace %s: "
                      "%s" % (body['metadata']['name'], namespace, e))
            raise

    def kube_delete_persistent_volume_claim(self, namespace, **kwargs):
        c = self._get_kubernetesclient()
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

        c = self._get_kubernetesclient()
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

        c = self._get_kubernetesclient()
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
