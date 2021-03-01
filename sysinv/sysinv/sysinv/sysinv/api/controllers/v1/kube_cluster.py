#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import pecan
from pecan import rest
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan
from six.moves.urllib.parse import urlparse

from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.common import constants
from sysinv.common import kubernetes
from sysinv.common import utils


class KubeCluster(base.APIBase):
    """API representation of a Kubernetes cluster."""

    cluster_name = wtypes.text
    "Cluster name"

    cluster_version = wtypes.text
    "Cluster active version"

    cluster_api_endpoint = wtypes.text
    "Cluster Public API Endpoint URL"

    cluster_ca_cert = wtypes.text
    "Cluster Root CA Certificate Data"

    admin_client_cert = wtypes.text
    "Administrative Client Certificate Data"

    admin_client_key = wtypes.text
    "Administrative Client Key Data"

    admin_user = wtypes.text
    "Administrative User Name"

    admin_token = wtypes.text
    "Administrative Service Account Token (base64 encoded)"

    @classmethod
    def convert(cls, kube_cluster_data):
        return KubeCluster(**kube_cluster_data)


class KubeClusterCollection(collection.Collection):
    """API representation of a collection of Kubernetes clusters."""

    kube_clusters = [KubeCluster]
    "A list containing Kubernetes cluster objects"

    def __init__(self, **kwargs):
        self._type = 'kube_clusters'

    @classmethod
    def convert(cls, kube_cluster_list):
        collection = KubeClusterCollection()
        collection.kube_clusters = [KubeCluster.convert(d)
                                    for d in kube_cluster_list]
        return collection


class KubeClusterController(rest.RestController):
    """REST controller for Kubernetes clusters."""

    def __init__(self, parent=None, **kwargs):
        self._parent = parent
        self._kube_operator = kubernetes.KubeOperator()

    @wsme_pecan.wsexpose(KubeClusterCollection)
    def get_all(self):
        """Retrieve a list of Kubernetes clusters."""

        # Currently only a single cluster is supported
        kube_cluster = self._get_kube_cluster(kubernetes.KUBERNETES_CLUSTER_DEFAULT)
        kube_clusters = [kube_cluster]

        return KubeClusterCollection.convert(kube_clusters)

    @wsme_pecan.wsexpose(KubeCluster, wtypes.text)
    def get_one(self, name=kubernetes.KUBERNETES_CLUSTER_DEFAULT):
        """Retrieve information about the given Kubernetes cluster."""

        kube_cluster = self._get_kube_cluster(name)

        return KubeCluster.convert(kube_cluster)

    def _get_kube_cluster(self, cluster_name):
        # Get the current version information
        cluster_version = self._kube_operator.kube_get_kubernetes_version()

        # Retrieve the default kubernetes cluster configuration
        cluster_config = self._kube_operator.kube_get_kubernetes_config()
        cluster_ca_cert = utils.get_file_content(cluster_config.ssl_ca_cert)
        admin_client_cert = utils.get_file_content(cluster_config.cert_file)
        admin_client_key = utils.get_file_content(cluster_config.key_file)

        # Build public endpoint from private endpoint
        endpoint_parsed = urlparse(cluster_config.host)
        endpoint_host = utils.format_url_address(self._get_oam_address())
        endpoint_netloc = "{}:{}".format(endpoint_host, endpoint_parsed.port)
        cluster_api_endpoint = endpoint_parsed._replace(
            netloc=endpoint_netloc).geturl()

        # Retrieve the default cluster admin service account token
        admin_user = kubernetes.KUBERNETES_ADMIN_USER
        admin_token = self._kube_operator.kube_get_service_account_token(
            admin_user, kubernetes.NAMESPACE_KUBE_SYSTEM)

        return {
            "cluster_name": cluster_name,
            "cluster_version": cluster_version,
            'cluster_api_endpoint': cluster_api_endpoint,
            "cluster_ca_cert": cluster_ca_cert,
            "admin_client_cert": admin_client_cert,
            "admin_client_key": admin_client_key,
            "admin_user": admin_user,
            "admin_token": admin_token
        }

    def _get_oam_address(self):
        address_name = utils.format_address_name(
            constants.CONTROLLER_HOSTNAME, constants.NETWORK_TYPE_OAM)
        address = pecan.request.dbapi.address_get_by_name(address_name)
        return address.address
