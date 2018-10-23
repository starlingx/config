#
# Copyright (c) 2013-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient import exc

CREATION_ATTRIBUTES = ['confirmed', 'name', 'services', 'capabilities',
                       'tier_uuid', 'cinder_pool_gib', 'glance_pool_gib',
                       'ephemeral_pool_gib', 'object_pool_gib',
                       'kube_pool_gib', 'object_gateway']
DISPLAY_ATTRIBUTES = ['object_gateway', 'ceph_total_space_gib',
                      'object_pool_gib', 'cinder_pool_gib',
                      'kube_pool_gib', 'glance_pool_gib', 'ephemeral_pool_gib',
                      'tier_name', 'tier_uuid']
PATCH_ATTRIBUTES = ['object_gateway', 'object_pool_gib',
                    'cinder_pool_gib', 'glance_pool_gib',
                    'ephemeral_pool_gib', 'kube_pool_gib']


class StorageCeph(base.Resource):
    def __repr__(self):
        return "<storage_ceph %s>" % self._info


class StorageCephManager(base.Manager):
    resource_class = StorageCeph

    @staticmethod
    def _path(id=None):
        return '/v1/storage_ceph/%s' % id if id else '/v1/storage_ceph'

    def list(self):
        return self._list(self._path(), "storage_ceph")

    def get(self, storceph_id=None):
        try:
            if storceph_id:
                return self._list(self._path(storceph_id))[0]
            else:
                return self._list(self._path(), "storage_ceph")[0]
        except IndexError:
            return None

    def create(self, **kwargs):
        new = {}
        for (key, value) in kwargs.items():
            if key in CREATION_ATTRIBUTES:
                new[key] = value
            else:
                raise exc.InvalidAttribute('%s' % key)
        return self._create(self._path(), new)

    def update(self, storceph_id, patch):
        return self._update(self._path(storceph_id), patch)

    def delete(self, storceph_id):
        return self._delete(self._path(storceph_id))
