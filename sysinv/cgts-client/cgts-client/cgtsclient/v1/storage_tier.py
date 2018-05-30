#
# Copyright (c) 2017-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient import exc


CREATION_ATTRIBUTES = ['cluster_uuid', 'name']


class StorageTier(base.Resource):
    def __repr__(self):
        return "<storage_tiers %s>" % self._info


class StorageTierManager(base.Manager):
    resource_class = StorageTier

    def list(self, cluster_uuid):
        path = '/v1/clusters/%s/storage_tiers' % cluster_uuid
        return self._list(path, "storage_tiers")

    def get(self, storage_tier_id):
        path = '/v1/storage_tiers/%s' % storage_tier_id
        try:
            return self._list(path)[0]
        except IndexError:
            return None

    def create(self, **kwargs):
        path = '/v1/storage_tiers/'
        new = {}
        for (key, value) in kwargs.items():
            if key in CREATION_ATTRIBUTES:
                new[key] = value
            else:
                raise exc.InvalidAttribute(key)
        return self._create(path, new)

    def delete(self, storage_tier_id):
        path = '/v1/storage_tiers/%s' % storage_tier_id
        return self._delete(path)

    def update(self, storage_tier_id, patch):
        path = '/v1/storage_tiers/%s' % storage_tier_id

        return self._update(path, patch)


def _find_storage_tier(cc, cluster, storage_tier):
    tier_list = cc.storage_tier.list(cluster.uuid)
    for t in tier_list:
        if t.name == storage_tier:
            return t
        elif t.uuid == storage_tier:
            return t
    else:
        raise exc.CommandError("Tier '%s' not associated with cluster '%s'."
                               % (storage_tier, cluster.name))
