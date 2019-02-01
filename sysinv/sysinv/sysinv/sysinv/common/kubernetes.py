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
