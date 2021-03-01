#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from cgtsclient.common import base


class KubeCluster(base.Resource):
    def __repr__(self):
        return "<kube_cluster %s>" % self._info


class KubeClusterManager(base.Manager):
    resource_class = KubeCluster

    @staticmethod
    def _path(name=None):
        return '/v1/kube_clusters/%s' % name if name else '/v1/kube_clusters'

    def list(self):
        """Retrieve the list of kubernetes clusters known to the system."""

        return self._list(self._path(), 'kube_clusters')

    def get(self, name):
        """Retrieve the details of a given kubernetes cluster

        :param name: kubernetes cluster name
        """
        try:
            return self._list(self._path(name))[0]
        except IndexError:
            return None
