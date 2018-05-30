#
# Copyright (c) 2016-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient import exc


CREATION_ATTRIBUTES = ['type', 'name', 'status', 'info', 'peers']


class Cluster(base.Resource):
    def __repr__(self):
        return "<clusters %s>" % self._info


class ClusterManager(base.Manager):
    resource_class = Cluster

    def list(self):
        path = '/v1/clusters'
        return self._list(path, "clusters")

    def get(self, cluster_id):
        path = '/v1/clusters/%s' % cluster_id
        try:
            return self._list(path)[0]
        except IndexError:
            return None

    def create(self, **kwargs):
        path = '/v1/clusters'
        new = {}
        for (key, value) in kwargs.items():
            if key in CREATION_ATTRIBUTES:
                new[key] = value
            else:
                raise exc.InvalidAttribute('%s' % key)
        return self._create(path, new)

    def delete(self, cluster_id):
        path = '/v1/clusters/%s' % cluster_id
        return self._delete(path)

    def update(self, cluster_id, patch):
        path = '/v1/clusters/%s' % cluster_id
        return self._update(path, patch)


def _find_cluster(cc, cluster):
    cluster_list = cc.cluster.list()
    for c in cluster_list:
        if c.name == cluster:
            return c
        if c.uuid == cluster:
            return c
    else:
        raise exc.CommandError('No cluster found with name or uuid %s. Verify '
                               'you have have specified a valid cluster.'
                               % cluster)
